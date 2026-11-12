/* See up_tls.h. */
#include "proxy/up_tls.h"

#include "core/log.h"

#include <errno.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#define READ_SIZE 16384
#define DRIVE_BUDGET 16 /* reads per wakeup, so one busy upstream cannot hog the loop */

#ifdef BST_TEST
unsigned long bst_test_uptls_full, bst_test_uptls_resumed;
#endif

/* ---- configuration ---- */

static void ctx_free(void *p)
{
	SSL_CTX_free(p);
}

static int ssl_fail(bst_err *e, const char *what, const char *name)
{
	unsigned long ec = ERR_get_error();
	char buf[256];
	ERR_error_string_n(ec, buf, sizeof buf);
	bst_err_set(e, "upstream %s: %s (%s)", name, what, ec ? buf : "no detail");
	ERR_clear_error();
	return -1;
}

static int new_session(SSL *ssl, SSL_SESSION *sess);

int bst_uptls_setup(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	for (size_t i = 0; i < cfg->global.nupstreams; i++) {
		bst_cfg_upstream *u = cfg->global.upstreams[i];
		if (!u->tls || u->tlsc.ctx != NULL)
			continue;
		ERR_clear_error();
		SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
		if (ctx == NULL)
			return ssl_fail(e, "cannot make a TLS context", u->name);
		if (bst_config_on_free(cfg, ctx_free, ctx, e) != 0) {
			SSL_CTX_free(ctx);
			return -1;
		}
		u->tlsc.ctx = ctx;
		int lo = u->tlsc.min_ver ? u->tlsc.min_ver : TLS1_2_VERSION;
		int hi = u->tlsc.max_ver ? u->tlsc.max_ver : TLS1_3_VERSION;
		if (SSL_CTX_set_min_proto_version(ctx, lo) != 1 ||
		    SSL_CTX_set_max_proto_version(ctx, hi) != 1)
			return ssl_fail(e, "cannot set the TLS versions", u->name);
		/* CA bundles are read now, in master, before the sandbox */
		if (u->tlsc.ca != NULL) {
			if (SSL_CTX_load_verify_locations(ctx, u->tlsc.ca, NULL) != 1) {
				ssl_fail(e, "tls ca: cannot load the CA bundle", u->name);
				bst_cfg_err_at(e, bst_cfg_src(c, &u->tlsc.loc));
				return -1;
			}
		} else if (!u->tlsc.no_verify && SSL_CTX_set_default_verify_paths(ctx) != 1) {
			return ssl_fail(e, "cannot load the system CA bundle", u->name);
		}
		SSL_CTX_set_verify(ctx, u->tlsc.no_verify ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);
		if ((u->tlsc.cert == NULL) != (u->tlsc.key == NULL)) {
			bst_err_set(e, "upstream %s: tls cert and tls key go together", u->name);
			bst_cfg_err_at(e, bst_cfg_src(c, &u->tlsc.loc));
			return -1;
		}
		if (u->tlsc.cert != NULL &&
		    (SSL_CTX_use_certificate_chain_file(ctx, u->tlsc.cert) != 1 ||
		     SSL_CTX_use_PrivateKey_file(ctx, u->tlsc.key, SSL_FILETYPE_PEM) != 1 ||
		     SSL_CTX_check_private_key(ctx) != 1)) {
			ssl_fail(e, "tls cert/tls key: cannot load the client certificate", u->name);
			bst_cfg_err_at(e, bst_cfg_src(c, &u->tlsc.loc));
			return -1;
		}
		SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ENABLE_PARTIAL_WRITE |
					      SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
		SSL_CTX_sess_set_new_cb(ctx, new_session);
		if (u->tlsc.no_verify)
			bst_cfg_warn_at(c, bst_cfg_src(c, &u->tlsc.loc),
					"upstream %s: tls verify off: the upstream's certificate is not "
					"checked, so anyone on the path can pose as it",
					u->name);
	}
	return 0;
}

/* ---- sessions, per worker by peer slot ---- */

static SSL_SESSION **g_sess;
static size_t g_nsess;

static SSL_SESSION **sess_slot(const bst_peer *p)
{
	if (p->state >= g_nsess) {
		size_t n = p->state + 64;
		SSL_SESSION **ns = realloc(g_sess, n * sizeof *ns);
		if (ns == NULL)
			return NULL;
		memset(ns + g_nsess, 0, (n - g_nsess) * sizeof *ns);
		g_sess = ns;
		g_nsess = n;
	}
	return &g_sess[p->state];
}

/* ---- the connection ---- */

struct bst_uptls {
	SSL *ssl;
	bst_sock *sk;
	bst_loop *l;
	const bst_cfg_upstream *u;
	const bst_peer *peer;
	int hs; /* 0 none, 1 running, 2 done */
	bst_done_cb hs_cb;
	void *hs_ud;
	bool rx_on;
	bst_recv_cb rx_cb;
	void *rx_ud;
	bst_chain *tx;
	bst_done_cb tx_cb;
	void *tx_ud;
	size_t tx_n;
	bool tx_kick; /* a send waits for its first drive */
	unsigned depth;
	bool dead;
	bool resumed;
	bool failed; /* a TLS-level error: the session is not reused */
};

static int new_session(SSL *ssl, SSL_SESSION *sess)
{
	bst_uptls *t = SSL_get_app_data(ssl);
	if (t == NULL || t->dead)
		return 0;
	SSL_SESSION **slot = sess_slot(t->peer);
	if (slot == NULL)
		return 0;
	if (*slot != NULL)
		SSL_SESSION_free(*slot);
	*slot = sess; /* the reference OpenSSL handed us */
	return 1;
}

static bool is_ip(const char *h)
{
	bst_ip ip;
	return bst_addr_parse((bst_str){ h, (uint32_t)strlen(h) }, &ip);
}

bst_uptls *bst_uptls_new(bst_loop *l, bst_sock *sk, const bst_cfg_upstream *u, const bst_peer *p)
{
	bst_uptls *t = calloc(1, sizeof *t);
	if (t == NULL)
		return NULL;
	ERR_clear_error();
	t->ssl = SSL_new(u->tlsc.ctx);
	if (t->ssl == NULL || SSL_set_fd(t->ssl, bst_sock_fd(sk)) != 1) {
		SSL_free(t->ssl);
		free(t);
		ERR_clear_error();
		return NULL;
	}
	t->sk = sk;
	t->l = l;
	t->u = u;
	t->peer = p;
	SSL_set_app_data(t->ssl, t);
	const char *name = u->tlsc.sni != NULL ? u->tlsc.sni : u->servers[p->server].host;
	if (!is_ip(name))
		(void)SSL_set_tlsext_host_name(t->ssl, name);
	if (!u->tlsc.no_verify) {
		X509_VERIFY_PARAM *vp = SSL_get0_param(t->ssl);
		X509_VERIFY_PARAM_set_hostflags(vp, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		if (is_ip(name))
			(void)X509_VERIFY_PARAM_set1_ip_asc(vp, name);
		else
			(void)X509_VERIFY_PARAM_set1_host(vp, name, 0);
	}
	SSL_SESSION **slot = sess_slot(p);
	if (slot != NULL && *slot != NULL)
		(void)SSL_set_session(t->ssl, *slot);
	return t;
}

bool bst_uptls_resumed(const bst_uptls *t)
{
	return t->resumed;
}

static void destroy(bst_uptls *t)
{
	SSL_set_app_data(t->ssl, NULL);
	/* SSL_free of a connection never shut down marks its session not resumable. Closing a
	 * connection that worked (idle timeout, keepalive off, a cut response) must keep the
	 * session; only a handshake or record failure (t->failed) gives it up. */
	if (!t->failed)
		SSL_set_shutdown(t->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
	SSL_free(t->ssl);
	free(t);
}

void bst_uptls_free(bst_uptls *t)
{
	if (t == NULL)
		return;
	t->dead = true;
	if (t->depth == 0)
		destroy(t);
}

static void on_poll(void *ud, uint32_t events, int err);

static void arm(bst_uptls *t, short want)
{
	if (want != 0 && !t->dead && bst_io_poll(t->sk, (uint32_t)want | POLLRDHUP, on_poll, t) != 0) {
		/* the poll cannot be armed: fail whatever waits on it */
		t->rx_on = false;
	}
}

/* Runs every pending operation as far as it goes; returns the events still waited for. */
static short drive(bst_uptls *t)
{
	short want = 0;
	if (t->hs == 1) {
		ERR_clear_error();
		int r = SSL_connect(t->ssl);
		if (r != 1) {
			int ec = SSL_get_error(t->ssl, r);
			if (ec == SSL_ERROR_WANT_READ)
				return POLLIN;
			if (ec == SSL_ERROR_WANT_WRITE)
				return POLLOUT;
			long vr = SSL_get_verify_result(t->ssl);
			const bst_up_server *s = &t->u->servers[t->peer->server];
			if (vr != X509_V_OK)
				bst_log(BST_LOG_ERROR, "upstream %s: server %s:%u: certificate verification "
						       "failed: %s", t->u->name, s->host, s->port,
					X509_verify_cert_error_string(vr));
			else
				bst_log(BST_LOG_ERROR, "upstream %s: server %s:%u: TLS handshake failed",
					t->u->name, s->host, s->port);
			ERR_clear_error();
			t->failed = true;
			t->hs = 0;
			t->hs_cb(t->hs_ud, 0, -EPROTO);
			return 0;
		}
		t->hs = 2;
		t->resumed = SSL_session_reused(t->ssl) == 1;
#ifdef BST_TEST
		if (t->resumed)
			bst_test_uptls_resumed++;
		else
			bst_test_uptls_full++;
#endif
		t->hs_cb(t->hs_ud, 0, 0);
		if (t->dead)
			return 0;
	}
	if (t->hs != 2)
		return 0;
	if (t->tx != NULL) {
		t->tx_kick = false;
		int err = 0;
		while (bst_chain_len(t->tx) > 0) {
			struct iovec iov[1];
			if (bst_chain_to_iov(t->tx, iov, 1) < 1) {
				err = -EIO; /* a file segment: never on this path */
				break;
			}
			ERR_clear_error();
			int r = SSL_write(t->ssl, iov[0].iov_base,
					  (int)(iov[0].iov_len > 65536 ? 65536 : iov[0].iov_len));
			if (r > 0) {
				bst_chain_consume(t->tx, (uint64_t)r);
				t->tx_n += (size_t)r;
				continue;
			}
			int ec = SSL_get_error(t->ssl, r);
			if (ec == SSL_ERROR_WANT_WRITE) {
				want |= POLLOUT;
			} else if (ec == SSL_ERROR_WANT_READ) {
				want |= POLLIN;
			} else {
				err = -EPIPE;
				t->failed = true;
				ERR_clear_error();
			}
			break;
		}
		if (err != 0 || bst_chain_len(t->tx) == 0) {
			bst_done_cb cb = t->tx_cb;
			size_t n = t->tx_n;
			t->tx = NULL;
			want &= (short)~POLLOUT;
			cb(t->tx_ud, n, err);
			if (t->dead)
				return 0;
		}
	}
	for (int i = 0; t->rx_on && i < DRIVE_BUDGET; i++) {
		bst_buf *b = bst_buf_new(READ_SIZE);
		if (b == NULL) {
			t->rx_on = false;
			t->rx_cb(t->rx_ud, NULL, -ENOMEM);
			return 0;
		}
		ERR_clear_error();
		int r = SSL_read(t->ssl, b->data, READ_SIZE);
		if (r > 0) {
			b->len = (size_t)r;
			t->rx_cb(t->rx_ud, b, 0); /* takes the reference */
			if (t->dead)
				return 0;
			continue;
		}
		bst_buf_unref(b);
		int ec = SSL_get_error(t->ssl, r);
		if (ec == SSL_ERROR_WANT_READ) {
			want |= POLLIN;
			break;
		}
		if (ec == SSL_ERROR_WANT_WRITE) {
			want |= POLLOUT;
			break;
		}
		t->rx_on = false;
		ERR_clear_error();
		/* close_notify is a clean end; a bare TCP close is reported as one too, and the HTTP
		 * reader decides whether the response was complete */
		bool eof = ec == SSL_ERROR_ZERO_RETURN || ec == SSL_ERROR_SYSCALL;
		t->failed = !eof;
		t->rx_cb(t->rx_ud, NULL, eof ? 0 : -EPROTO);
		return 0;
	}
	if (t->rx_on && !(want & POLLIN))
		want |= POLLOUT; /* the budget ran out with plaintext perhaps buffered in SSL: come
				  * back on the next loop turn, not on new bytes */
	if (t->tx != NULL && t->tx_kick)
		want |= POLLOUT;
	return want;
}

static void run(bst_uptls *t)
{
	t->depth++;
	short want = drive(t);
	t->depth--;
	if (t->dead) {
		if (t->depth == 0)
			destroy(t);
		return;
	}
	arm(t, want);
}

static void on_poll(void *ud, uint32_t events, int err)
{
	(void)events;
	(void)err; /* SSL reports the failure itself on the next call */
	run(ud);
}

/* Operations started from outside: nothing runs inside the call. A one-shot POLLOUT poll comes
 * back on the next loop turn (the socket is almost always writable), which is when drive runs. */
static void kick(bst_uptls *t)
{
	if (t->depth == 0)
		arm(t, POLLOUT | (t->rx_on ? POLLIN : 0));
}

void bst_uptls_handshake(bst_uptls *t, bst_done_cb cb, void *ud)
{
	t->hs = 1;
	t->hs_cb = cb;
	t->hs_ud = ud;
	kick(t);
}

int bst_uptls_recv_start(bst_uptls *t, bst_recv_cb cb, void *ud)
{
	if (t->rx_on)
		return -EBUSY;
	t->rx_on = true;
	t->rx_cb = cb;
	t->rx_ud = ud;
	if (t->depth == 0)
		arm(t, POLLIN | POLLOUT); /* SSL may hold plaintext already: look on the next turn */
	return 0;
}

int bst_uptls_recv_stop(bst_uptls *t)
{
	t->rx_on = false;
	return 0;
}

int bst_uptls_send(bst_uptls *t, bst_chain *c, bst_done_cb cb, void *ud)
{
	if (t->tx != NULL)
		return -EBUSY;
	t->tx = c;
	t->tx_cb = cb;
	t->tx_ud = ud;
	t->tx_n = 0;
	t->tx_kick = true;
	kick(t);
	return 0;
}

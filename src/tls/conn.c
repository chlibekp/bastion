#include "tls/conn.h"
#include "tls/early.h"

#include "core/buf.h"
#include "core/chain.h"
#include "core/counters.h"
#include "core/log.h"
#include "tls/ktls.h"
#include "tls/sni.h"
#include "io/aio.h"
#include "io/net.h"
#include "io/sock.h"

#include <errno.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STAGE_SIZE (64u * 1024u) /* one file read staged for user-space encryption */
#define KICK_MS 1u		 /* the loop has no "run soon": the shortest timer is 1 ms */

static bst_counter_id c_ok = BST_COUNTER_INVALID, c_fail = BST_COUNTER_INVALID,
		      c_timeout = BST_COUNTER_INVALID;

void bst_tls_conn_init(void)
{
	const char *h = "TLS handshakes by result";
	c_ok = bst_counter_register("bastion_tls_handshakes_total", h, "result=ok");
	c_fail = bst_counter_register("bastion_tls_handshakes_total", h, "result=failed");
	c_timeout = bst_counter_register("bastion_tls_handshakes_total", h, "result=timeout");
}

typedef struct tconn {
	bst_transport base;
	bst_loop *loop;
	bst_sock *s;
	SSL *ssl;
	bst_timer t_hs, t_kick, t_done;
	bst_tls_ready_cb ready;
	void *ready_ud;
	bst_http_on_tls policy;
	const bst_cfg_tls_profile *profile;
	bst_tls_sni sni;
	char cv[96], dn[512], san[512], fp[72]; /* $ssl_client_*, made on first use */
	bool cv_done, dn_done, san_done, fp_done;
	bool ktx, krx; /* the record layer is in the kernel for sending, for receiving */
	bool up;     /* handshake finished */
	/* 0-RTT (tls/early.h): the HTTP connection starts when early data arrives, before the handshake
	 * is complete; `serving` says the transport was handed out, `up` that the handshake finished. */
	enum { E_NONE, E_INIT, E_READING, E_FINISHED } early;
	bool serving;
	bst_buf *first;	/* the first early data, read before the transport existed */
	int late_err;	/* a failure after the transport was handed out, for the next recv */
	bool dead;   /* closed by the owner: freed when nothing references it */
	bool failed; /* a fatal TLS or socket error: no close_notify on close */
	unsigned depth, jobs;
	/* receive */
	bst_recv_cb rcb;
	void *rud;
	bool recv_on;
	/* send */
	bst_chain *chain;
	bst_done_cb scb;
	void *sud;
	size_t sent;
	bool send_on, done_pending;
	int done_err;
	/* staged file data, and the aio read that fills it */
	unsigned char *stage;
	size_t st_len, st_off;
	bool reading;
	int rd_fd;
	off_t rd_off;
	size_t rd_want;
	ssize_t rd_res;
	int rd_errno;
} tconn;

static void drive(tconn *c);

static void enter(tconn *c)
{
	c->depth++;
}

static void destroy(tconn *c)
{
	bst_timer_cancel(&c->t_hs);
	bst_timer_cancel(&c->t_kick);
	bst_timer_cancel(&c->t_done);
	if (c->s != NULL)
		bst_sock_close(c->s);
	SSL_free(c->ssl);
	if (c->first != NULL)
		bst_buf_unref(c->first);
	free(c->stage);
	free(c);
}

static void leave(tconn *c)
{
	if (--c->depth == 0 && c->dead && c->jobs == 0)
		destroy(c);
}

static void on_kick(void *ud)
{
	drive(ud);
}

static void kick(tconn *c)
{
	if (!c->dead)
		bst_loop_timer_arm(c->loop, &c->t_kick, KICK_MS, on_kick, c);
}

static void on_poll(void *ud, uint32_t events, int err)
{
	(void)events, (void)err;
	drive(ud);
}

static void arm(tconn *c, uint32_t want)
{
	if (want != 0 && !c->dead && c->s != NULL)
		(void)bst_io_poll(c->s, want, on_poll, c);
}

/* ---- handshake ---- */

static const char PLAIN_ON_TLS[] = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
				   "Content-Length: 58\r\nConnection: close\r\n\r\n"
				   "Client sent a plain HTTP request to an HTTPS port.\r\n\r\n\r\n";

/* The caller's callback runs once; the connection is gone afterwards. */
static void hs_end(tconn *c, bst_counter_id why, bool http_on_tls)
{
	bst_counter_add(why, 1);
	if (http_on_tls && c->policy == BST_HTTP_ON_TLS_RESPOND && c->s != NULL)
		(void)!write(bst_sock_fd(c->s), PLAIN_ON_TLS, sizeof PLAIN_ON_TLS - 1);
	c->failed = true;
	bst_tls_ready_cb cb = c->ready;
	c->ready = NULL;
	c->dead = true;
	bst_sock_close(c->s);
	c->s = NULL;
	cb(c->ready_ud, NULL);
	if (c->depth == 0 && c->jobs == 0)
		destroy(c);
}

static void send_finish(tconn *c, int err);

/* A failure after the transport went out (the handshake behind early data did not complete): the
 * HTTP connection hears it as a receive error, or a send error, or at its next receive. */
static void late_fail(tconn *c, int err)
{
	bst_timer_cancel(&c->t_hs);
	c->failed = true;
	if (c->recv_on) {
		c->recv_on = false;
		c->rcb(c->rud, NULL, err);
	} else if (c->send_on) {
		send_finish(c, err);
	} else {
		c->late_err = err;
	}
}

static void on_hs_timeout(void *ud)
{
	tconn *c = ud;
	bst_log(BST_LOG_DEBUG, "tls: handshake timed out");
	enter(c);
	if (c->serving) {
		bst_counter_add(c_timeout, 1);
		late_fail(c, -ETIMEDOUT);
	} else {
		hs_end(c, c_timeout, false);
	}
	leave(c);
}

/* The handshake is complete: counters, the timer, kernel TLS. */
static void hs_up(tconn *c)
{
	bst_timer_cancel(&c->t_hs);
	c->up = true;
	bst_counter_add(c_ok, 1);
	bst_tls_ktls_note(c->ssl, c->profile, &c->ktx, &c->krx);
}

/* Completes the handshake behind early data. 1 done, 0 waiting (*want set), -1 failed (*err). */
static int finish_hs(tconn *c, uint32_t *want, int *err)
{
	ERR_clear_error();
	int r = SSL_accept(c->ssl);
	if (r == 1) {
		hs_up(c);
		return 1;
	}
	int e = SSL_get_error(c->ssl, r);
	if (e == SSL_ERROR_WANT_READ) {
		*want |= POLLIN;
		return 0;
	}
	if (e == SSL_ERROR_WANT_WRITE) {
		*want |= POLLOUT;
		return 0;
	}
	bst_counter_add(c_fail, 1);
	*err = e == SSL_ERROR_SYSCALL && errno != 0 ? -errno : -EPROTO;
	return -1;
}

static void hs_fail(tconn *c, int e)
{
	bool http = ERR_GET_REASON(ERR_peek_error()) == SSL_R_HTTP_REQUEST;
	if (e == SSL_ERROR_SSL)
		bst_log(BST_LOG_DEBUG, "tls: handshake failed: %s", ERR_reason_error_string(ERR_peek_error()));
	hs_end(c, c_fail, http);
}

static void hs_step(tconn *c)
{
	ERR_clear_error();
	if (c->early == E_INIT) {
		/* With early data possible the first read decides: data starts the HTTP connection now,
		 * none (or a refusal) is an ordinary handshake. */
		bst_buf *b = bst_buf_new(BST_RECV_BUF_SIZE);
		if (b == NULL) {
			hs_end(c, c_fail, false);
			return;
		}
		size_t n = 0;
		int r = SSL_read_early_data(c->ssl, b->data, b->cap, &n);
		if (r == SSL_READ_EARLY_DATA_SUCCESS) {
			b->len = n;
			c->first = b;
			c->early = E_READING;
			c->serving = true;
			bst_tls_ready_cb cb = c->ready;
			c->ready = NULL;
			cb(c->ready_ud, &c->base);
			return;
		}
		bst_buf_unref(b);
		if (r != SSL_READ_EARLY_DATA_FINISH) {
			int e = SSL_get_error(c->ssl, 0);
			if (e == SSL_ERROR_WANT_READ)
				arm(c, POLLIN);
			else if (e == SSL_ERROR_WANT_WRITE)
				arm(c, POLLOUT);
			else
				hs_fail(c, e);
			return;
		}
		c->early = E_FINISHED;
	}
	int r = SSL_accept(c->ssl);
	if (r == 1) {
		hs_up(c);
		c->serving = true;
		bst_tls_ready_cb cb = c->ready;
		c->ready = NULL;
		cb(c->ready_ud, &c->base);
		return;
	}
	int e = SSL_get_error(c->ssl, r);
	if (e == SSL_ERROR_WANT_READ)
		arm(c, POLLIN);
	else if (e == SSL_ERROR_WANT_WRITE)
		arm(c, POLLOUT);
	else
		hs_fail(c, e);
}

/* ---- receive ---- */

/* Early data before the handshake is complete: 1 when a read was done (data delivered or the end of
 * early data seen), 0 when it must wait (*want set), -1 when the connection failed (reported). */
static int early_recv(tconn *c, uint32_t *want)
{
	if (c->first != NULL) {
		bst_buf *b = c->first;
		c->first = NULL;
		c->rcb(c->rud, b, 0);
		return 1;
	}
	if (c->early == E_READING) {
		bst_buf *b = bst_buf_new(BST_RECV_BUF_SIZE);
		if (b == NULL) {
			late_fail(c, -ENOMEM);
			return -1;
		}
		size_t n = 0;
		ERR_clear_error();
		int r = SSL_read_early_data(c->ssl, b->data, b->cap, &n);
		if (r == SSL_READ_EARLY_DATA_SUCCESS) {
			b->len = n;
			c->rcb(c->rud, b, 0);
			return 1;
		}
		bst_buf_unref(b);
		if (r == SSL_READ_EARLY_DATA_FINISH) {
			c->early = E_FINISHED;
			return 1;
		}
		int e = SSL_get_error(c->ssl, 0);
		if (e == SSL_ERROR_WANT_READ) {
			*want |= POLLIN;
			return 0;
		}
		if (e == SSL_ERROR_WANT_WRITE) {
			*want |= POLLOUT;
			return 0;
		}
		bst_counter_add(c_fail, 1);
		late_fail(c, -EPROTO);
		return -1;
	}
	int err = 0;
	int f = finish_hs(c, want, &err);
	if (f < 0)
		late_fail(c, err);
	return f;
}

static void recv_step(tconn *c, uint32_t *want)
{
	if (c->late_err != 0) {
		int err = c->late_err;
		c->late_err = 0;
		c->recv_on = false;
		c->rcb(c->rud, NULL, err);
		return;
	}
	for (unsigned n = 0; n < BST_RECV_BUDGET && c->recv_on && !c->dead; n++) {
		if (!c->up) {
			int r = early_recv(c, want);
			if (r <= 0)
				return;
			continue;
		}
		bst_buf *b = bst_buf_new(BST_RECV_BUF_SIZE);
		if (b == NULL) {
			c->recv_on = false;
			c->failed = true;
			c->rcb(c->rud, NULL, -ENOMEM);
			return;
		}
		ERR_clear_error();
		int r = SSL_read(c->ssl, b->data, (int)b->cap);
		if (r > 0) {
			b->len = (size_t)r;
			c->rcb(c->rud, b, 0);
			continue;
		}
		bst_buf_unref(b);
		int e = SSL_get_error(c->ssl, r);
		if (e == SSL_ERROR_WANT_READ) {
			*want |= POLLIN;
			return;
		}
		if (e == SSL_ERROR_WANT_WRITE) {
			*want |= POLLOUT;
			return;
		}
		c->recv_on = false;
		if (e == SSL_ERROR_ZERO_RETURN || (e == SSL_ERROR_SYSCALL && errno == 0)) {
			/* close_notify, or the peer vanished without one: both end the stream */
			c->rcb(c->rud, NULL, 0);
		} else {
			int err = e == SSL_ERROR_SYSCALL ? -errno : -EPROTO;
			if (e == SSL_ERROR_SSL && c->ktx)
				bst_tls_ktls_closed(); /* a KeyUpdate the kernel cannot follow */
			c->failed = true;
			c->rcb(c->rud, NULL, err != 0 ? err : -EIO);
		}
		return;
	}
	if (c->recv_on && !c->dead)
		kick(c); /* budget spent: let the other sockets run, then continue */
}

/* ---- send ---- */

static void send_finish(tconn *c, int err)
{
	c->send_on = false;
	bst_done_cb cb = c->scb;
	void *ud = c->sud;
	size_t n = c->sent;
	c->scb = NULL;
	if (err != 0)
		c->failed = true;
	cb(ud, n, err);
}

static void on_done_timer(void *ud)
{
	tconn *c = ud;
	enter(c);
	c->done_pending = false;
	if (!c->dead && c->send_on)
		send_finish(c, c->done_err);
	leave(c);
}

static void file_work(void *arg)
{
	tconn *c = arg;
	c->rd_res = pread(c->rd_fd, c->stage, c->rd_want, c->rd_off);
	c->rd_errno = c->rd_res < 0 ? errno : 0;
}

static void file_done(void *arg)
{
	tconn *c = arg;
	enter(c);
	c->jobs--;
	c->reading = false;
	if (!c->dead && c->send_on) {
		if (c->rd_res > 0) {
			c->st_off = 0;
			c->st_len = (size_t)c->rd_res;
		} else {
			/* the file ended before its segment did, or the read failed */
			c->done_err = -(c->rd_res < 0 ? c->rd_errno : EIO);
			send_finish(c, c->done_err);
		}
		if (!c->dead && c->send_on)
			drive(c);
	}
	leave(c);
}

/* Writes p[0..n). 1 when all n went out, 0 when blocked (*want set), -1 on error. */
static int write_all(tconn *c, const unsigned char *p, size_t n, size_t *done, uint32_t *want)
{
	*done = 0;
	while (*done < n) {
		ERR_clear_error();
		size_t chunk = n - *done < 16384 ? n - *done : 16384;
		int r;
		if (!c->up && c->early == E_READING) {
			/* half-RTT data: written before the handshake is complete (tls/early.h) */
			size_t w = 0;
			r = SSL_write_early_data(c->ssl, p + *done, chunk, &w) == 1 ? (int)w : 0;
		} else if (!c->up && c->early == E_FINISHED) {
			int err = 0;
			int f = finish_hs(c, want, &err);
			if (f == 0)
				return 0;
			if (f < 0) {
				errno = -err;
				return -1;
			}
			continue;
		} else {
			r = SSL_write(c->ssl, p + *done, (int)chunk);
		}
		if (r > 0) {
			*done += (size_t)r;
			continue;
		}
		int e = SSL_get_error(c->ssl, r);
		if (e == SSL_ERROR_WANT_WRITE) {
			*want |= POLLOUT;
			return 0;
		}
		if (e == SSL_ERROR_WANT_READ) {
			*want |= POLLIN;
			return 0;
		}
		return -1;
	}
	return 1;
}

static void send_step(tconn *c, uint32_t *want)
{
	size_t budget = BST_SEND_BUDGET;
	while (c->send_on && !c->dead) {
		if (bst_chain_len(c->chain) == 0) {
			/* the callback must not run inside bst_io_send's caller */
			if (!c->done_pending) {
				c->done_pending = true;
				c->done_err = 0;
				bst_loop_timer_arm(c->loop, &c->t_done, KICK_MS, on_done_timer, c);
			}
			return;
		}
		if (budget == 0) {
			kick(c);
			return;
		}
		const unsigned char *p;
		size_t n;
		struct iovec iov[1];
		bool staged = c->st_off < c->st_len;
		if (staged) {
			p = c->stage + c->st_off;
			n = c->st_len - c->st_off;
		} else if (bst_chain_to_iov(c->chain, iov, 1) > 0) {
			p = iov[0].iov_base;
			n = iov[0].iov_len;
		} else {
			int fd;
			off_t off, len;
			if (!bst_chain_front_file(c->chain, &fd, &off, &len)) {
				send_finish(c, -EIO);
				return;
			}
			if (c->reading)
				return;
			if (c->stage == NULL && (c->stage = malloc(STAGE_SIZE)) == NULL) {
				send_finish(c, -ENOMEM);
				return;
			}
			c->rd_fd = fd;
			c->rd_off = off;
			c->rd_want = (uint64_t)len < STAGE_SIZE ? (size_t)len : STAGE_SIZE;
			c->reading = true;
			c->jobs++;
			int rc = bst_aio_submit(c->loop, file_work, file_done, c);
			if (rc != 0) {
				c->jobs--;
				c->reading = false;
				if (rc == -EAGAIN) {
					kick(c); /* the pool queue is full: try again shortly */
					return;
				}
				send_finish(c, rc);
			}
			return;
		}
		size_t done;
		int rc = write_all(c, p, n, &done, want);
		if (done > 0) {
			bst_chain_consume(c->chain, done);
			c->sent += done;
			budget = done < budget ? budget - done : 0;
			if (staged)
				c->st_off += done;
		}
		if (rc == 0)
			return;
		if (rc < 0) {
			send_finish(c, errno != 0 && errno != EAGAIN ? -errno : -ECONNRESET);
			return;
		}
	}
}

/* ---- the driver ---- */

static void drive(tconn *c)
{
	if (c->dead)
		return;
	enter(c);
	if (!c->serving) {
		hs_step(c);
	} else {
		uint32_t want = 0;
		if (!c->up && c->early == E_FINISHED) {
			/* the handshake behind early data must finish even when HTTP is not reading */
			int err = 0;
			if (finish_hs(c, &want, &err) < 0)
				late_fail(c, err);
		}
		if (!c->dead && c->send_on)
			send_step(c, &want);
		if (!c->dead && c->recv_on)
			recv_step(c, &want);
		if (!c->dead)
			arm(c, want);
	}
	leave(c);
}

/* ---- transport ops ---- */

static int t_recv_start(bst_transport *t, bst_recv_cb cb, void *ud)
{
	tconn *c = (tconn *)t;
	if (c->recv_on)
		return -EBUSY;
	c->rcb = cb;
	c->rud = ud;
	c->recv_on = true;
	/* data may already be decrypted or buffered inside OpenSSL, where no socket event will
	 * announce it */
	kick(c);
	return 0;
}

static int t_recv_stop(bst_transport *t)
{
	tconn *c = (tconn *)t;
	c->recv_on = false;
	return 0;
}

static int t_send(bst_transport *t, bst_chain *chain, bst_done_cb cb, void *ud)
{
	tconn *c = (tconn *)t;
	if (c->ktx) /* the kernel encrypts: files go out with sendfile or splice */
		return bst_io_send(c->s, chain, cb, ud);
	if (c->send_on)
		return -EBUSY;
	c->chain = chain;
	c->scb = cb;
	c->sud = ud;
	c->sent = 0;
	c->st_off = c->st_len = 0;
	c->send_on = true;
	c->done_pending = false;
	enter(c);
	uint32_t want = 0;
	send_step(c, &want);
	if (!c->dead)
		arm(c, want | (c->recv_on ? POLLIN : 0));
	leave(c);
	return 0;
}

static bool t_zero_copy(const bst_transport *t)
{
	return ((const tconn *)t)->ktx;
}

static void t_shutdown(bst_transport *t, bst_done_cb cb, void *ud)
{
	tconn *c = (tconn *)t;
	if (!c->failed && c->up) {
		ERR_clear_error();
		(void)SSL_shutdown(c->ssl); /* close_notify: best effort, advisory */
	}
	int rc = c->s != NULL ? bst_sock_shutdown_wr(c->s) : -EBADF;
	if (cb != NULL)
		cb(ud, 0, rc);
}

static void t_close(bst_transport *t)
{
	tconn *c = (tconn *)t;
	if (c->dead)
		return;
	if (c->up && !c->failed) {
		ERR_clear_error();
		(void)SSL_shutdown(c->ssl); /* a clean end tells the peer the data is complete */
	}
	c->dead = true;
	c->recv_on = c->send_on = false;
	bst_timer_cancel(&c->t_kick);
	bst_timer_cancel(&c->t_done);
	bst_sock_close(c->s);
	c->s = NULL;
	if (c->depth == 0 && c->jobs == 0)
		destroy(c);
}

static const bst_transport_ops tls_ops = {
	.recv_start = t_recv_start,
	.recv_stop = t_recv_stop,
	.send = t_send,
	.zero_copy_files = t_zero_copy,
	.shutdown = t_shutdown,
	.close = t_close,
};

static const char *client_var(tconn *c, const char *name)
{
	X509 *x = SSL_get0_peer_certificate(c->ssl);
	if (strcmp(name, "client_verify") == 0) {
		long r = SSL_get_verify_result(c->ssl);
		if (x == NULL)
			snprintf(c->cv, sizeof c->cv, "NONE");
		else if (r == X509_V_OK)
			snprintf(c->cv, sizeof c->cv, "SUCCESS");
		else
			snprintf(c->cv, sizeof c->cv, "FAILED:%s", X509_verify_cert_error_string(r));
		return c->cv;
	}
	if (x == NULL)
		return NULL;
	if (strcmp(name, "client_s_dn") == 0) {
		BIO *b = BIO_new(BIO_s_mem());
		c->dn[0] = '\0';
		if (b != NULL) {
			X509_NAME_print_ex(b, X509_get_subject_name(x), 0, XN_FLAG_RFC2253);
			int n = BIO_read(b, c->dn, (int)sizeof c->dn - 1);
			c->dn[n > 0 ? n : 0] = '\0';
			BIO_free(b);
		}
		return c->dn;
	}
	if (strcmp(name, "client_san_dns") == 0) {
		GENERAL_NAMES *gn = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
		size_t n = 0;
		c->san[0] = '\0';
		for (int i = 0; gn != NULL && i < sk_GENERAL_NAME_num(gn); i++) {
			const GENERAL_NAME *g = sk_GENERAL_NAME_value(gn, i);
			if (g->type != GEN_DNS)
				continue;
			const char *d = (const char *)ASN1_STRING_get0_data(g->d.dNSName);
			size_t dl = (size_t)ASN1_STRING_length(g->d.dNSName);
			if (n + dl + 2 >= sizeof c->san)
				break;
			if (n > 0)
				c->san[n++] = ',';
			memcpy(c->san + n, d, dl);
			n += dl;
			c->san[n] = '\0';
		}
		GENERAL_NAMES_free(gn);
		return c->san;
	}
	if (strcmp(name, "client_fingerprint") == 0) {
		unsigned char md[EVP_MAX_MD_SIZE];
		unsigned len = 0;
		if (X509_digest(x, EVP_sha256(), md, &len) != 1)
			return NULL;
		for (unsigned i = 0; i < len && i < 32; i++)
			snprintf(c->fp + 2 * i, 3, "%02x", md[i]);
		return c->fp;
	}
	return NULL;
}

bool bst_tls_client_verified(const bst_transport *t)
{
	if (t == NULL || t->ops != &tls_ops)
		return false;
	const tconn *c = (const tconn *)t;
	return SSL_get0_peer_certificate(c->ssl) != NULL && SSL_get_verify_result(c->ssl) == X509_V_OK;
}

const bst_cfg_server *bst_tls_chosen_server(const bst_transport *t)
{
	return t != NULL && t->ops == &tls_ops ? ((const tconn *)t)->sni.chosen : NULL;
}

const char *bst_tls_var(const bst_transport *t, const char *name)
{
	if (t == NULL || t->ops != &tls_ops)
		return NULL;
	const tconn *c = (const tconn *)t;
	if (strcmp(name, "ja4") == 0)
		return c->sni.ja4[0] != '\0' ? c->sni.ja4 : NULL;
	if (strncmp(name, "client_", 7) == 0)
		return client_var((tconn *)(uintptr_t)c, name);
	if (strcmp(name, "protocol") == 0)
		return SSL_get_version(c->ssl);
	if (strcmp(name, "cipher") == 0)
		return SSL_CIPHER_get_name(SSL_get_current_cipher(c->ssl));
	if (strcmp(name, "session_reused") == 0)
		return SSL_session_reused(c->ssl) ? "r" : ".";
	return NULL;
}

int bst_tls_accept(bst_loop *loop, int fd, SSL_CTX *ctx, const bst_cfg_tls_profile *profile,
		   const bst_listener_set *set, bst_http_on_tls policy, bst_tls_ready_cb cb, void *ud)
{
	tconn *c = calloc(1, sizeof *c);
	bst_sock *s = c != NULL ? bst_sock_wrap(loop, fd) : NULL;
	SSL *ssl = s != NULL ? SSL_new(ctx) : NULL;
	if (ssl == NULL || SSL_set_fd(ssl, fd) != 1) {
		SSL_free(ssl);
		if (s != NULL)
			bst_sock_close(s);
		else
			close(fd);
		free(c);
		ERR_clear_error();
		return -1;
	}
	SSL_set_accept_state(ssl);
	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
				  SSL_MODE_RELEASE_BUFFERS);
	c->base.ops = &tls_ops;
	c->loop = loop;
	c->s = s;
	c->ssl = ssl;
	c->ready = cb;
	c->ready_ud = ud;
	c->policy = policy;
	c->profile = profile;
	c->sni.set = set;
	c->early = bst_early_active() ? E_INIT : E_NONE;
	bst_tls_sni_attach(ssl, &c->sni);
	bst_timer_init(&c->t_hs);
	bst_timer_init(&c->t_kick);
	bst_timer_init(&c->t_done);
	bst_loop_timer_arm(loop, &c->t_hs, profile->handshake_timeout_ms, on_hs_timeout, c);
	/* the ClientHello is rarely there yet; waiting costs nothing */
	enter(c);
	arm(c, POLLIN);
	leave(c);
	return 0;
}

const bst_cfg_server *bst_tls_sni_server(const bst_transport *t)
{
	return t != NULL && t->ops == &tls_ops ? ((const tconn *)t)->sni.server : NULL;
}

bool bst_tls_early_active(const bst_transport *t)
{
	if (t == NULL || t->ops != &tls_ops)
		return false;
	const tconn *c = (const tconn *)t;
	return c->serving && !c->up;
}

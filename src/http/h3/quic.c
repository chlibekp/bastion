/* See quic.h. */
#include "http/h3/quic.h"

#include "core/counters.h"
#include "core/hash.h"
#include "core/log.h"
#include "core/wheel.h"
#include "http/h3/cid.h"
#include "http/h3/h3_bridge.h"
#include "io/sock.h"
#include "proc/worker.h"
#include "tls/conn.h"
#include "tls/tickets.h"

#include <errno.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>

/* ---- counters ---- */

enum { C_OPENED, C_CLOSED, C_RETRY, C_VN, C_RESET, C_REFUSED, C_DROPPED, C_N };
static bst_counter_id ctr[C_N] = { BST_COUNTER_INVALID, BST_COUNTER_INVALID, BST_COUNTER_INVALID,
				   BST_COUNTER_INVALID, BST_COUNTER_INVALID, BST_COUNTER_INVALID,
				   BST_COUNTER_INVALID };

void bst_quic_init(void)
{
	static const char *const kinds[C_N] = { "kind=opened", "kind=closed", "kind=retry", "kind=vn",
						"kind=reset", "kind=refused", "kind=dropped" };
	for (int i = 0; i < C_N; i++)
		ctr[i] = bst_counter_register("bastion_quic_events_total",
					      "QUIC connections opened and closed, and the stateless "
					      "answers to datagrams for no connection",
					      kinds[i]);
	if (ngtcp2_crypto_ossl_init() != 0)
		bst_log(BST_LOG_ERROR, "quic: ngtcp2_crypto_ossl_init failed");
}

/* ---- structures ---- */

typedef struct cid_ent {
	struct cid_ent *next;  /* bucket chain */
	struct cid_ent *cnext; /* the connection's own list */
	bst_quic_conn *c;
	uint8_t len;
	uint8_t id[NGTCP2_MAX_CIDLEN];
} cid_ent;

struct bst_quic_conn {
	bst_quic_endpoint *ep;
	ngtcp2_conn *q;
	SSL *ssl;
	ngtcp2_crypto_ossl_ctx *octx;
	ngtcp2_crypto_conn_ref ref;
	bst_timer timer;
	cid_ent *cids;
	bst_quic_conn *prev, *next;	  /* every connection of the endpoint */
	bst_quic_conn *bnext;		  /* waiting for room in the send queue */
	bool blocked;
	bool hs_done, closing, draining, dead;
	uint8_t close_pkt[BST_QUIC_PKT_MAX];
	size_t close_len;
	bst_sockaddr peer;		  /* where the close packet goes */
	bst_ip close_src;
	uint64_t rx_pkts, tx_pkts;
	bst_transport *t;		  /* TLS over QUIC (tls/conn.h): $ssl_*, SNI */
	bst_h3_conn *h3;		  /* HTTP/3, once the first stream data or the handshake came */
	ngtcp2_ccerr err;		  /* why a callback failed, when it knows */
	bool has_err;
};

typedef struct txpkt {
	bst_udp_pkt meta;
	uint8_t data[BST_QUIC_PKT_MAX];
} txpkt;

struct bst_quic_endpoint {
	bst_quic_ep_cfg cfg;
	bst_cfg_quic q;
	bst_sock *sock;
	/* connection IDs */
	cid_ent **buckets;
	size_t nbuckets, nids;
	uint8_t hkey[16];
	bst_quic_conn *conns;
	bst_quic_conn *blocked;
	/* send queue: a ring over the pool; [head, head+inflight) is in bst_udp_send */
	txpkt *pool;
	size_t head, count, inflight;
	bst_udp_pkt sendv[BST_UDP_BATCH];
	bool draining;
	bst_quic_stats st;
};

static uint64_t now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * NGTCP2_SECONDS + (uint64_t)t.tv_nsec;
}

static void count(int which)
{
	bst_counter_add(ctr[which], 1);
}

/* A datagram nothing answers. Logged at debug level only: a flood must not flood the log. */
static void drop(bst_quic_endpoint *ep, size_t len, const char *why)
{
	ep->st.dropped++;
	count(C_DROPPED);
	bst_log(BST_LOG_DEBUG, "quic: dropped datagram len=%zu: %s", len, why);
}

static bool from_sockaddr(const ngtcp2_sockaddr *sa, bst_sockaddr *out)
{
	memset(out, 0, sizeof *out);
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *s4 = (const struct sockaddr_in *)(const void *)sa;
		out->ip.family = BST_IP_V4;
		memcpy(out->ip.b, &s4->sin_addr, 4);
		out->port = ntohs(s4->sin_port);
		return true;
	}
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)(const void *)sa;
		out->ip.family = BST_IP_V6;
		memcpy(out->ip.b, &s6->sin6_addr, 16);
		out->port = ntohs(s6->sin6_port);
		return true;
	}
	return false;
}

/* ---- the connection ID table ---- */

static size_t bucket_of(const bst_quic_endpoint *ep, const uint8_t *id, size_t len)
{
	return (size_t)(bst_siphash13(ep->hkey, id, len) & (ep->nbuckets - 1));
}

static bst_quic_conn *cid_find(const bst_quic_endpoint *ep, const uint8_t *id, size_t len)
{
	for (cid_ent *e = ep->buckets[bucket_of(ep, id, len)]; e != NULL; e = e->next)
		if (e->len == len && memcmp(e->id, id, len) == 0)
			return e->c;
	return NULL;
}

static void grow(bst_quic_endpoint *ep)
{
	size_t nb = ep->nbuckets * 2;
	cid_ent **b = calloc(nb, sizeof *b);
	if (b == NULL)
		return; /* longer chains, still correct */
	cid_ent **old = ep->buckets;
	size_t onb = ep->nbuckets;
	ep->buckets = b;
	ep->nbuckets = nb;
	for (size_t i = 0; i < onb; i++)
		for (cid_ent *e = old[i], *n; e != NULL; e = n) {
			n = e->next;
			size_t k = bucket_of(ep, e->id, e->len);
			e->next = b[k];
			b[k] = e;
		}
	free(old);
}

static int cid_add(bst_quic_endpoint *ep, bst_quic_conn *c, const uint8_t *id, size_t len)
{
	if (len == 0 || len > NGTCP2_MAX_CIDLEN || cid_find(ep, id, len) != NULL)
		return len == 0 ? 0 : -1; /* a zero-length ID routes nothing */
	cid_ent *e = malloc(sizeof *e);
	if (e == NULL)
		return -1;
	e->c = c;
	e->len = (uint8_t)len;
	memcpy(e->id, id, len);
	size_t k = bucket_of(ep, id, len);
	e->next = ep->buckets[k];
	ep->buckets[k] = e;
	e->cnext = c->cids;
	c->cids = e;
	if (++ep->nids > ep->nbuckets * 2)
		grow(ep);
	return 0;
}

static void cid_unlink(bst_quic_endpoint *ep, cid_ent *e)
{
	for (cid_ent **p = &ep->buckets[bucket_of(ep, e->id, e->len)]; *p != NULL; p = &(*p)->next)
		if (*p == e) {
			*p = e->next;
			ep->nids--;
			return;
		}
}

static void cid_del(bst_quic_endpoint *ep, bst_quic_conn *c, const uint8_t *id, size_t len)
{
	for (cid_ent **p = &c->cids; *p != NULL; p = &(*p)->cnext)
		if ((*p)->len == len && memcmp((*p)->id, id, len) == 0) {
			cid_ent *e = *p;
			*p = e->cnext;
			cid_unlink(ep, e);
			free(e);
			return;
		}
}

/* ---- sending ---- */

static void kick(bst_quic_endpoint *ep);
static void conn_write(bst_quic_conn *c);
static int ensure_h3(bst_quic_conn *c);

static void resume_blocked(bst_quic_endpoint *ep)
{
	bst_quic_conn *list = ep->blocked;
	ep->blocked = NULL;
	while (list != NULL && ep->count < BST_QUIC_TXQ) {
		bst_quic_conn *c = list;
		list = c->bnext;
		c->blocked = false;
		conn_write(c);
	}
	while (list != NULL) { /* still no room: back on the list, in order */
		bst_quic_conn *c = list;
		list = c->bnext;
		c->bnext = ep->blocked;
		ep->blocked = c;
	}
}

static void on_sent(void *ud, size_t bytes, int err)
{
	bst_quic_endpoint *ep = ud;
	(void)bytes;
	if (err < 0 && err != -ECANCELED)
		bst_log(BST_LOG_DEBUG, "quic: send: %s", strerror(-err));
	ep->head = (ep->head + ep->inflight) % BST_QUIC_TXQ;
	ep->count -= ep->inflight;
	ep->inflight = 0;
	kick(ep);
	resume_blocked(ep);
}

static void kick(bst_quic_endpoint *ep)
{
	if (ep->cfg.sink != NULL) { /* tests and fuzzing: everything goes out at once */
		while (ep->count > 0) {
			ep->cfg.sink(ep->cfg.sink_ud, &ep->pool[ep->head].meta);
			ep->head = (ep->head + 1) % BST_QUIC_TXQ;
			ep->count--;
		}
		return;
	}
	if (ep->inflight > 0 || ep->count == 0 || ep->sock == NULL)
		return;
	size_t n = ep->count < BST_UDP_BATCH ? ep->count : BST_UDP_BATCH;
	for (size_t i = 0; i < n; i++)
		ep->sendv[i] = ep->pool[(ep->head + i) % BST_QUIC_TXQ].meta;
	ep->inflight = n;
	int rc = bst_udp_send(ep->sock, ep->sendv, (int)n, on_sent, ep);
	if (rc != 0) { /* not started, or a bad packet: drop the batch, never stall the queue */
		bst_log(BST_LOG_DEBUG, "quic: send: %s", strerror(-rc));
		ep->head = (ep->head + n) % BST_QUIC_TXQ;
		ep->count -= n;
		ep->inflight = 0;
	}
}

/* The next free packet of the pool, or NULL when the queue is full. Committed by enqueue. */
static txpkt *slot_next(bst_quic_endpoint *ep)
{
	if (ep->count >= BST_QUIC_TXQ)
		return NULL;
	return &ep->pool[(ep->head + ep->count) % BST_QUIC_TXQ];
}

static void enqueue(bst_quic_endpoint *ep, txpkt *p, size_t len, const bst_sockaddr *to,
		    const bst_ip *from, uint8_t ecn)
{
	memset(&p->meta, 0, sizeof p->meta);
	p->meta.data = p->data;
	p->meta.len = len;
	p->meta.dst = *to;
	if (from != NULL && from->family != 0)
		p->meta.src = *from;
	p->meta.ecn = ecn & 3;
	ep->count++;
}

/* A stateless answer (Retry, VN, reset, refusal): a copy into the queue, dropped when it is full. */
static void send_raw(bst_quic_endpoint *ep, const uint8_t *data, size_t len, const bst_sockaddr *to,
		     const bst_sockaddr *from)
{
	txpkt *p = slot_next(ep);
	if (p == NULL || len > sizeof p->data)
		return;
	memcpy(p->data, data, len);
	enqueue(ep, p, len, to, from != NULL ? &from->ip : NULL, 0);
	kick(ep);
}

/* ---- connection lifetime ---- */

static void conn_free(bst_quic_conn *c)
{
	bst_quic_endpoint *ep = c->ep;
	bst_timer_cancel(&c->timer);
	while (c->cids != NULL) {
		cid_ent *e = c->cids;
		c->cids = e->cnext;
		cid_unlink(ep, e);
		free(e);
	}
	if (c->blocked)
		for (bst_quic_conn **p = &ep->blocked; *p != NULL; p = &(*p)->bnext)
			if (*p == c) {
				*p = c->bnext;
				break;
			}
	if (c->prev != NULL)
		c->prev->next = c->next;
	else
		ep->conns = c->next;
	if (c->next != NULL)
		c->next->prev = c->prev;
	bst_h3_conn_free(c->h3); /* every unfinished handler is told on_reset */
	/* ngtcp2_crypto_ossl: the ngtcp2_conn must outlive the SSL (spikes/quic/README.md); the SNI
	 * state in the transport must too. */
	SSL_free(c->ssl);
	bst_tls_quic_free(c->t);
	ngtcp2_conn_del(c->q);
	ngtcp2_crypto_ossl_ctx_del(c->octx);
	if (!c->hs_done)
		ep->st.half_open--;
	ep->st.live--;
	ep->st.closed++;
	count(C_CLOSED);
	bst_log(BST_LOG_DEBUG, "quic: closed slot=%u rx=%llu tx=%llu live=%llu", (unsigned)ep->cfg.slot,
		(unsigned long long)c->rx_pkts, (unsigned long long)c->tx_pkts,
		(unsigned long long)ep->st.live);
	free(c);
	if (ep->cfg.worker != NULL)
		bst_worker_conn_closed(ep->cfg.worker);
}

static void on_timer(void *ud);

static void arm(bst_quic_conn *c, uint64_t ts)
{
	uint64_t exp = ngtcp2_conn_get_expiry2(c->q);
	if (c->closing || c->draining)
		exp = ts + 3 * ngtcp2_conn_get_pto2(c->q);
	if (exp == UINT64_MAX)
		return;
	uint64_t ms = exp > ts ? (exp - ts + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS : 1;
	bst_loop_timer_arm(c->ep->cfg.loop, &c->timer, ms ? ms : 1, on_timer, c);
}

/* Ends the connection with CONNECTION_CLOSE carrying err, then keeps it for its closing period
 * to repeat the close to a peer that keeps sending. */
static void conn_close(bst_quic_conn *c, const ngtcp2_ccerr *err)
{
	if (c->closing || c->draining)
		return;
	ngtcp2_path_storage ps;
	ngtcp2_path_storage_zero(&ps);
	ngtcp2_pkt_info pi;
	uint64_t ts = now_ns();
	ngtcp2_ssize n = ngtcp2_conn_write_connection_close(c->q, &ps.path, &pi, c->close_pkt,
							    sizeof c->close_pkt, err, ts);
	if (n <= 0 || !from_sockaddr(ps.path.remote.addr, &c->peer)) {
		conn_free(c); /* nothing to repeat (no keys yet): free at once */
		return;
	}
	bst_sockaddr local;
	c->close_src.family = 0;
	if (from_sockaddr(ps.path.local.addr, &local))
		c->close_src = local.ip;
	c->close_len = (size_t)n;
	c->closing = true;
	txpkt *p = slot_next(c->ep);
	if (p != NULL) {
		memcpy(p->data, c->close_pkt, c->close_len);
		enqueue(c->ep, p, c->close_len, &c->peer, &c->close_src, 0);
		kick(c->ep);
	}
	arm(c, ts);
}

static void conn_fail(bst_quic_conn *c, int liberr)
{
	ngtcp2_ccerr err;
	ngtcp2_ccerr_default(&err);
	if (c->has_err) /* a callback (HTTP/3) said why */
		err = c->err;
	else if (liberr == NGTCP2_ERR_CRYPTO)
		ngtcp2_ccerr_set_tls_alert(&err, ngtcp2_conn_get_tls_alert2(c->q), NULL, 0);
	else
		ngtcp2_ccerr_set_liberr(&err, liberr, NULL, 0);
	conn_close(c, &err);
}

static void conn_write(bst_quic_conn *c)
{
	bst_quic_endpoint *ep = c->ep;
	if (c->closing || c->draining)
		return;
	uint64_t ts = now_ns();
	for (;;) {
		txpkt *p = slot_next(ep);
		if (p == NULL) {
			if (!c->blocked) {
				c->blocked = true;
				c->bnext = ep->blocked;
				ep->blocked = c;
			}
			break;
		}
		ngtcp2_path_storage ps;
		ngtcp2_path_storage_zero(&ps);
		ngtcp2_pkt_info pi;
		/* HTTP/3 first: what nghttp3 has for a stream goes into this packet with it
		 * (ngtcp2's examples/server.cc write_streams). */
		nghttp3_conn *h3 = c->h3 != NULL ? bst_h3_nghttp3(c->h3) : NULL;
		int64_t sid = -1;
		int fin = 0;
		nghttp3_vec vec[16];
		nghttp3_ssize nv = 0;
		if (h3 != NULL && ngtcp2_conn_get_max_data_left(c->q) > 0) {
			nv = nghttp3_conn_writev_stream(h3, &sid, &fin, vec, 16);
			if (nv < 0) {
				ngtcp2_ccerr_set_application_error(&c->err, nghttp3_err_infer_quic_app_error_code((int)nv),
								   NULL, 0);
				c->has_err = true;
				conn_fail(c, NGTCP2_ERR_CALLBACK_FAILURE);
				return;
			}
		}
		uint32_t fl = NGTCP2_WRITE_STREAM_FLAG_MORE | (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0);
		ngtcp2_ssize ndata = -1;
		ngtcp2_ssize n = ngtcp2_conn_writev_stream(c->q, &ps.path, &pi, p->data, sizeof p->data, &ndata, fl,
							   sid, (const ngtcp2_vec *)(const void *)vec, (size_t)nv, ts);
		if (n < 0) {
			if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
				nghttp3_conn_block_stream(h3, sid);
				continue;
			}
			if (n == NGTCP2_ERR_STREAM_SHUT_WR) {
				nghttp3_conn_shutdown_stream_write(h3, sid);
				continue;
			}
			if (n == NGTCP2_ERR_WRITE_MORE) {
				if (nghttp3_conn_add_write_offset(h3, sid, (uint64_t)ndata) != 0) {
					conn_fail(c, NGTCP2_ERR_INTERNAL);
					return;
				}
				continue;
			}
			conn_fail(c, (int)n);
			return;
		}
		if (ndata >= 0 && h3 != NULL && nghttp3_conn_add_write_offset(h3, sid, (uint64_t)ndata) != 0) {
			conn_fail(c, NGTCP2_ERR_INTERNAL);
			return;
		}
		if (n == 0)
			break;
		bst_sockaddr to, from;
		if (!from_sockaddr(ps.path.remote.addr, &to))
			break;
		bool have_from = from_sockaddr(ps.path.local.addr, &from);
		enqueue(ep, p, (size_t)n, &to, have_from ? &from.ip : NULL, pi.ecn);
		c->tx_pkts++;
	}
	ngtcp2_conn_update_pkt_tx_time(c->q, ts);
	kick(ep);
	arm(c, ts);
}

static void on_timer(void *ud)
{
	bst_quic_conn *c = ud;
	uint64_t ts = now_ns();
	if (c->closing || c->draining) {
		conn_free(c);
		return;
	}
	int rv = ngtcp2_conn_handle_expiry(c->q, ts);
	if (rv == NGTCP2_ERR_IDLE_CLOSE || rv == NGTCP2_ERR_HANDSHAKE_TIMEOUT) {
		conn_free(c); /* silent: RFC 9000 section 10.1 */
		return;
	}
	if (rv != 0) {
		conn_fail(c, rv);
		return;
	}
	conn_write(c);
}

/* ---- ngtcp2 callbacks ---- */

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *r)
{
	return ((bst_quic_conn *)r->user_data)->q;
}

static void rand_cb(uint8_t *dest, size_t len, const ngtcp2_rand_ctx *rctx)
{
	(void)rctx;
	if (RAND_bytes(dest, (int)len) != 1)
		memset(dest, 0, len); /* only PADDING and PATH_CHALLENGE fill come from here */
}

static int new_cid(ngtcp2_conn *q, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *tok, size_t len,
		   void *ud)
{
	(void)q;
	bst_quic_conn *c = ud;
	if (bst_cid_generate(c->ep->cfg.slot, cid->data, len) != 0)
		return NGTCP2_ERR_CALLBACK_FAILURE;
	cid->datalen = len;
	if (bst_token_reset(tok->data, &c->ep->cfg.secrets, cid) != 0 ||
	    cid_add(c->ep, c, cid->data, cid->datalen) != 0)
		return NGTCP2_ERR_CALLBACK_FAILURE;
	return 0;
}

static int remove_cid(ngtcp2_conn *q, const ngtcp2_cid *cid, void *ud)
{
	(void)q;
	bst_quic_conn *c = ud;
	cid_del(c->ep, c, cid->data, cid->datalen);
	return 0;
}

static int handshake_done(ngtcp2_conn *q, void *ud)
{
	bst_quic_conn *c = ud;
	c->hs_done = true;
	c->ep->st.half_open--;
	bst_tls_quic_handshake_done(c->t);
	if (ensure_h3(c) != 0)
		return NGTCP2_ERR_CALLBACK_FAILURE;
	/* A NEW_TOKEN lets this client skip the Retry round trip next time (RFC 9000 section 8.1.3). */
	bst_sockaddr peer;
	uint8_t tok[BST_TOKEN_MAX];
	if (from_sockaddr(ngtcp2_conn_get_path(q)->remote.addr, &peer)) {
		ngtcp2_ssize n = bst_token_regular(tok, &c->ep->cfg.secrets, &peer, now_ns());
		if (n > 0)
			(void)ngtcp2_conn_submit_new_token(q, tok, (size_t)n);
	}
	bst_log(BST_LOG_DEBUG, "quic: handshake done slot=%u version=0x%x", (unsigned)c->ep->cfg.slot,
		ngtcp2_conn_get_negotiated_version(q));
	return 0;
}

/* A client that moved (NAT rebinding, a new network) proved its new address. Reaching this worker
 * at all is the reuseport program's doing (xdp/reuseport.h). */
static int path_validated(ngtcp2_conn *q, uint32_t flags, const ngtcp2_path *path,
			  const ngtcp2_path *fallback, ngtcp2_path_validation_result res, void *ud)
{
	(void)q, (void)flags, (void)path, (void)fallback;
	bst_quic_conn *c = ud;
	bst_log(BST_LOG_DEBUG, "quic: path validation %s slot=%u",
		res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS ? "succeeded" : "failed",
		(unsigned)c->ep->cfg.slot);
	return 0;
}

/* ---- HTTP/3 (h3_bridge.h) ---- */

static void h3_write(void *ud)
{
	conn_write(ud);
}

static void h3_fail(void *ud, uint64_t code)
{
	bst_quic_conn *c = ud;
	ngtcp2_ccerr err;
	ngtcp2_ccerr_default(&err);
	ngtcp2_ccerr_set_application_error(&err, code, NULL, 0);
	conn_close(c, &err);
}

/* A callback failed for an HTTP/3 reason: the connection closes with its code. */
static int h3_error(bst_quic_conn *c, int rv)
{
	ngtcp2_ccerr_set_application_error(&c->err, nghttp3_err_infer_quic_app_error_code(rv), NULL, 0);
	c->has_err = true;
	return NGTCP2_ERR_CALLBACK_FAILURE;
}

/* HTTP/3 starts with the first stream data (0-RTT included) or the handshake, whichever comes
 * first. An endpoint without a listener set (tests, fuzzing) serves no HTTP/3: stream data is
 * taken and its credit given back. */
static int ensure_h3(bst_quic_conn *c)
{
	if (c->h3 != NULL || c->ep->cfg.set == NULL || c->t == NULL)
		return 0;
	bst_h3_env env = {
		.q = c->q,
		.loop = c->ep->cfg.loop,
		.w = c->ep->cfg.worker,
		.set = c->ep->cfg.set,
		.cfg = &c->ep->q,
		.t = c->t,
		.write = h3_write,
		.fail = h3_fail,
		.ud = c,
	};
	(void)from_sockaddr(ngtcp2_conn_get_path(c->q)->remote.addr, &env.peer);
	c->h3 = bst_h3_conn_new(&env);
	return c->h3 != NULL ? 0 : h3_error(c, NGHTTP3_ERR_NOMEM);
}

static int recv_stream_data(ngtcp2_conn *q, uint32_t flags, int64_t sid, uint64_t off,
			    const uint8_t *data, size_t len, void *ud, void *sud)
{
	(void)off, (void)sud;
	bst_quic_conn *c = ud;
	int rv = ensure_h3(c);
	if (rv != 0)
		return rv;
	if (c->h3 == NULL) {
		ngtcp2_conn_extend_max_stream_offset(q, sid, len);
		ngtcp2_conn_extend_max_offset(q, len);
		return 0;
	}
	rv = bst_h3_recv(c->h3, sid, data, len, (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
	return rv != 0 ? h3_error(c, rv) : 0;
}

static int acked_stream_data(ngtcp2_conn *q, int64_t sid, uint64_t off, uint64_t len, void *ud, void *sud)
{
	(void)q, (void)off, (void)sud;
	bst_quic_conn *c = ud;
	int rv = c->h3 != NULL ? bst_h3_acked(c->h3, sid, len) : 0;
	return rv != 0 ? h3_error(c, rv) : 0;
}

static int stream_close(ngtcp2_conn *q, uint32_t flags, int64_t sid, uint64_t code, void *ud, void *sud)
{
	(void)q, (void)sud;
	bst_quic_conn *c = ud;
	if (c->h3 == NULL)
		return 0;
	if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET))
		code = BST_H3_NO_ERROR;
	int rv = bst_h3_stream_closed(c->h3, sid, code);
	if (rv != 0)
		return h3_error(c, rv);
	if (ngtcp2_is_bidi_stream(sid))
		(void)ngtcp2_conn_extend_max_streams_bidi(q, 1); /* a request slot is free again */
	return 0;
}

static int stream_reset(ngtcp2_conn *q, int64_t sid, uint64_t final_size, uint64_t code, void *ud, void *sud)
{
	(void)q, (void)final_size, (void)code, (void)sud;
	bst_quic_conn *c = ud;
	int rv = c->h3 != NULL ? bst_h3_peer_reset(c->h3, sid) : 0;
	return rv != 0 ? h3_error(c, rv) : 0;
}

static int stream_stop_sending(ngtcp2_conn *q, int64_t sid, uint64_t code, void *ud, void *sud)
{
	(void)q, (void)code, (void)sud;
	bst_quic_conn *c = ud;
	int rv = c->h3 != NULL ? bst_h3_peer_stop_sending(c->h3, sid) : 0;
	return rv != 0 ? h3_error(c, rv) : 0;
}

static int extend_max_remote_bidi(ngtcp2_conn *q, uint64_t max, void *ud)
{
	(void)q;
	bst_quic_conn *c = ud;
	return c->h3 != NULL ? bst_h3_max_streams(c->h3, max) : 0;
}

static int extend_max_stream_data(ngtcp2_conn *q, int64_t sid, uint64_t max, void *ud, void *sud)
{
	(void)q, (void)max, (void)sud;
	bst_quic_conn *c = ud;
	int rv = c->h3 != NULL ? bst_h3_unblock(c->h3, sid) : 0;
	return rv != 0 ? h3_error(c, rv) : 0;
}

/* ---- accepting ---- */

static void fill_versions(const bst_cfg_quic *q, ngtcp2_settings *s)
{
	s->preferred_versions = q->versions;
	s->preferred_versionslen = q->nversions;
	s->available_versions = q->versions;
	s->available_versionslen = q->nversions;
}

static bool version_served(const bst_quic_endpoint *ep, uint32_t v)
{
	for (uint32_t i = 0; i < ep->q.nversions; i++)
		if (ep->q.versions[i] == v)
			return true;
	return false;
}

static void send_close_stateless(bst_quic_endpoint *ep, const ngtcp2_pkt_hd *hd, uint64_t code,
				 const bst_sockaddr *src, const bst_sockaddr *dst)
{
	uint8_t out[256];
	ngtcp2_ssize n = ngtcp2_crypto_write_connection_close(out, sizeof out, hd->version, &hd->scid,
							      &hd->dcid, code, NULL, 0);
	if (n > 0)
		send_raw(ep, out, (size_t)n, src, dst);
}

static void send_retry(bst_quic_endpoint *ep, const ngtcp2_pkt_hd *hd, const bst_sockaddr *src,
		       const bst_sockaddr *dst)
{
	ngtcp2_cid scid;
	scid.datalen = BST_CID_LEN;
	uint8_t tok[BST_TOKEN_MAX], out[BST_QUIC_PKT_MAX];
	if (bst_cid_generate(ep->cfg.slot, scid.data, BST_CID_LEN) != 0)
		return;
	ngtcp2_ssize tl = bst_token_retry(tok, &ep->cfg.secrets, hd->version, src, &scid, &hd->dcid,
					  now_ns());
	if (tl < 0)
		return;
	ngtcp2_ssize n = ngtcp2_crypto_write_retry(out, sizeof out, hd->version, &hd->scid, &scid,
						   &hd->dcid, tok, (size_t)tl);
	if (n <= 0)
		return;
	send_raw(ep, out, (size_t)n, src, dst);
	ep->st.retries++;
	count(C_RETRY);
	bst_log(BST_LOG_DEBUG, "quic: Retry slot=%u half_open=%llu", (unsigned)ep->cfg.slot,
		(unsigned long long)ep->st.half_open);
}

static bst_quic_conn *conn_new(bst_quic_endpoint *ep, const ngtcp2_pkt_hd *hd, const ngtcp2_path *path,
			       const ngtcp2_cid *odcid, int token_type)
{
	bst_quic_conn *c = calloc(1, sizeof *c);
	if (c == NULL)
		return NULL;
	c->ep = ep;
	bst_timer_init(&c->timer);
	ngtcp2_callbacks cb = {
		.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.rand = rand_cb,
		.update_key = ngtcp2_crypto_update_key_cb,
		.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
		.get_new_connection_id2 = new_cid,
		.remove_connection_id = remove_cid,
		.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
		.recv_stream_data = recv_stream_data,
		.handshake_completed = handshake_done,
		.path_validation = path_validated,
		.acked_stream_data_offset = acked_stream_data,
		.stream_close = stream_close,
		.stream_reset = stream_reset,
		.stream_stop_sending = stream_stop_sending,
		.extend_max_remote_streams_bidi = extend_max_remote_bidi,
		.extend_max_stream_data = extend_max_stream_data,
	};
	ngtcp2_settings s;
	ngtcp2_settings_default(&s);
	uint64_t ts = now_ns();
	s.initial_ts = ts;
	s.cc_algo = ep->q.cc == BST_QUIC_CC_BBR    ? NGTCP2_CC_ALGO_BBR
		    : ep->q.cc == BST_QUIC_CC_RENO ? NGTCP2_CC_ALGO_RENO
						   : NGTCP2_CC_ALGO_CUBIC;
	s.handshake_timeout = ep->q.handshake_timeout_ms * NGTCP2_MILLISECONDS;
	fill_versions(&ep->q, &s);
	if (token_type != NGTCP2_TOKEN_TYPE_UNKNOWN) {
		s.token = hd->token;
		s.tokenlen = hd->tokenlen;
		s.token_type = (ngtcp2_token_type)token_type;
	}
	ngtcp2_transport_params p;
	ngtcp2_transport_params_default(&p);
	p.initial_max_streams_bidi = ep->q.max_streams_bidi;
	p.initial_max_streams_uni = ep->q.max_streams_uni;
	p.initial_max_data = ep->q.initial_max_data;
	p.initial_max_stream_data_bidi_remote = ep->q.initial_max_stream_data;
	p.initial_max_stream_data_uni = ep->q.initial_max_stream_data;
	p.max_idle_timeout = ep->q.idle_timeout_ms * NGTCP2_MILLISECONDS;
	p.original_dcid = odcid != NULL ? *odcid : hd->dcid;
	p.original_dcid_present = 1;
	if (odcid != NULL) {
		p.retry_scid = hd->dcid;
		p.retry_scid_present = 1;
	}
	ngtcp2_cid scid;
	scid.datalen = BST_CID_LEN;
	if (bst_cid_generate(ep->cfg.slot, scid.data, BST_CID_LEN) != 0 ||
	    bst_token_reset(p.stateless_reset_token, &ep->cfg.secrets, &scid) != 0)
		goto fail_early;
	p.stateless_reset_token_present = 1;
	if (ngtcp2_conn_server_new(&c->q, &hd->scid, &scid, path, hd->version, &cb, &s, &p, NULL, c) != 0)
		goto fail_early;
	ERR_clear_error();
	c->ssl = SSL_new((SSL_CTX *)(uintptr_t)ep->q.ssl_ctx);
	if (c->ssl == NULL || ngtcp2_crypto_ossl_ctx_new(&c->octx, c->ssl) != 0 ||
	    ngtcp2_crypto_ossl_configure_server_session(c->ssl) != 0)
		goto fail;
	if (SSL_get_max_early_data(c->ssl) != 0) /* without it every 0-RTT attempt is refused */
		SSL_set_quic_tls_early_data_enabled(c->ssl, 1);
	if (ep->cfg.set != NULL && (c->t = bst_tls_quic_transport(c->ssl, ep->cfg.set)) == NULL)
		goto fail;
	c->ref.get_conn = get_conn;
	c->ref.user_data = c;
	SSL_set_app_data(c->ssl, &c->ref);
	SSL_set_accept_state(c->ssl);
	ngtcp2_conn_set_tls_native_handle(c->q, c->octx);
	if (cid_add(ep, c, scid.data, scid.datalen) != 0 || cid_add(ep, c, hd->dcid.data, hd->dcid.datalen) != 0)
		goto fail;
	c->next = ep->conns;
	if (ep->conns != NULL)
		ep->conns->prev = c;
	ep->conns = c;
	ep->st.live++;
	ep->st.half_open++;
	ep->st.opened++;
	count(C_OPENED);
	if (ep->cfg.worker != NULL)
		bst_worker_conn_opened(ep->cfg.worker);
	bst_log(BST_LOG_DEBUG, "quic: open slot=%u live=%llu half_open=%llu", (unsigned)ep->cfg.slot,
		(unsigned long long)ep->st.live, (unsigned long long)ep->st.half_open);
	return c;
fail:
	while (c->cids != NULL) {
		cid_ent *e = c->cids;
		c->cids = e->cnext;
		cid_unlink(ep, e);
		free(e);
	}
	SSL_free(c->ssl);
	bst_tls_quic_free(c->t);
	ngtcp2_conn_del(c->q);
	ngtcp2_crypto_ossl_ctx_del(c->octx);
	ERR_clear_error();
fail_early:
	free(c);
	return NULL;
}

/* A datagram for no connection: answered without state, or a new connection. */
static void unknown(bst_quic_endpoint *ep, const uint8_t *data, size_t len, const ngtcp2_version_cid *vc,
		    const bst_sockaddr *src, const bst_sockaddr *dst, const ngtcp2_path *path, uint8_t ecn)
{
	if (!(data[0] & 0x80)) { /* short header: a connection some worker lost, or garbage */
		/* RFC 9000 section 10.3: smaller than the trigger, at least 21 bytes, random bits. */
		if (!ep->q.stateless_reset || ep->draining || len < 22) {
			drop(ep, len, "short header for no connection");
			return;
		}
		ngtcp2_cid cid;
		ngtcp2_cid_init(&cid, vc->dcid, vc->dcidlen);
		uint8_t tok[NGTCP2_STATELESS_RESET_TOKENLEN], rnd[64], out[128];
		size_t total = len - 1 < 64 ? len - 1 : 64;
		size_t rlen = total - 1 - NGTCP2_STATELESS_RESET_TOKENLEN;
		if (bst_token_reset(tok, &ep->cfg.secrets, &cid) != 0 || RAND_bytes(rnd, (int)rlen) != 1)
			return;
		ngtcp2_ssize n = ngtcp2_pkt_write_stateless_reset(out, sizeof out, tok, rnd, rlen);
		if (n > 0) {
			send_raw(ep, out, (size_t)n, src, dst);
			ep->st.resets++;
			count(C_RESET);
			bst_log(BST_LOG_DEBUG, "quic: stateless reset slot=%u", (unsigned)ep->cfg.slot);
		}
		return;
	}
	ngtcp2_pkt_hd hd;
	if (ep->draining) {
		drop(ep, len, "stopping");
		return;
	}
	if (len < NGTCP2_MAX_UDP_PAYLOAD_SIZE) { /* RFC 9000 section 14.1 */
		drop(ep, len, "Initial under 1200 bytes");
		return;
	}
	if (ngtcp2_accept(&hd, data, len) != 0 || hd.type != NGTCP2_PKT_INITIAL) {
		drop(ep, len, "long header for no connection");
		return;
	}
	if (ep->st.live >= ep->q.max_connections) {
		send_close_stateless(ep, &hd, NGTCP2_CONNECTION_REFUSED, src, dst);
		ep->st.refused++;
		count(C_REFUSED);
		bst_log(BST_LOG_DEBUG, "quic: refused slot=%u live=%llu", (unsigned)ep->cfg.slot,
			(unsigned long long)ep->st.live);
		return;
	}
	uint64_t ts = now_ns();
	ngtcp2_cid odcid;
	const ngtcp2_cid *retried = NULL;
	int token_type = NGTCP2_TOKEN_TYPE_UNKNOWN;
	if (hd.tokenlen > 0 && hd.token[0] == NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2) {
		if (bst_token_retry_check(&odcid, hd.token, hd.tokenlen, &ep->cfg.secrets, hd.version, src,
					  &hd.dcid, ts) != 0) {
			send_close_stateless(ep, &hd, NGTCP2_INVALID_TOKEN, src, dst);
			drop(ep, len, "invalid Retry token");
			return;
		}
		retried = &odcid;
		token_type = NGTCP2_TOKEN_TYPE_RETRY;
	} else if (hd.tokenlen > 0 &&
		   bst_token_regular_check(hd.token, hd.tokenlen, &ep->cfg.secrets, src, ts) == 0) {
		token_type = NGTCP2_TOKEN_TYPE_NEW_TOKEN;
	}
	bool must_retry = ep->q.retry == BST_QUIC_RETRY_ALWAYS ||
			  (ep->q.retry == BST_QUIC_RETRY_AUTO && ep->st.half_open >= ep->q.retry_threshold);
	if (token_type == NGTCP2_TOKEN_TYPE_UNKNOWN && must_retry) {
		send_retry(ep, &hd, src, dst);
		return;
	}
	bst_quic_conn *c = conn_new(ep, &hd, path, retried, token_type);
	if (c == NULL) {
		drop(ep, len, "no memory for a connection");
		return;
	}
	ngtcp2_pkt_info pi = { .ecn = ecn };
	ERR_clear_error();
	/* ngtcp2 asserts monotonic time per connection: not before conn_new's initial_ts. */
	int rv = ngtcp2_conn_read_pkt(c->q, path, &pi, data, len, now_ns());
	c->rx_pkts++;
	if (rv == NGTCP2_ERR_RETRY) {
		/* The ClientHello does not start in this Initial: ngtcp2 buffers it only for a
		 * validated address, so the client proves its address first, whatever quic_retry says. */
		conn_free(c);
		send_retry(ep, &hd, src, dst);
		return;
	}
	if (rv != 0) {
		if (rv == NGTCP2_ERR_DROP_CONN || rv == NGTCP2_ERR_DRAINING)
			conn_free(c);
		else
			conn_fail(c, rv);
		return;
	}
	conn_write(c);
}

void bst_quic_endpoint_input(bst_quic_endpoint *ep, const uint8_t *data, size_t len,
			     const bst_sockaddr *src, const bst_sockaddr *dst, uint8_t ecn)
{
	if (len == 0)
		return;
	ngtcp2_version_cid vc;
	int rv = ngtcp2_pkt_decode_version_cid(&vc, data, len, BST_CID_LEN);
	if (rv == 0 && (data[0] & 0x80) && (vc.version == 0 || !version_served(ep, vc.version)))
		rv = vc.version == 0 ? NGTCP2_ERR_INVALID_ARGUMENT : NGTCP2_ERR_VERSION_NEGOTIATION;
	if (rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
		/* Only for a datagram a client could have sent as a first Initial: VN is never larger
		 * than its trigger, and a small spoofed one gets nothing (RFC 9000 section 6.1). */
		if (len < NGTCP2_MAX_UDP_PAYLOAD_SIZE || ep->draining) {
			drop(ep, len, "unknown version in a small datagram");
			return;
		}
		uint8_t out[256], r;
		if (RAND_bytes(&r, 1) != 1)
			r = 0x5a;
		ngtcp2_ssize n = ngtcp2_pkt_write_version_negotiation(out, sizeof out, r, vc.scid, vc.scidlen,
								     vc.dcid, vc.dcidlen, ep->q.versions,
								     ep->q.nversions);
		if (n > 0) {
			send_raw(ep, out, (size_t)n, src, dst);
			ep->st.vn++;
			count(C_VN);
			bst_log(BST_LOG_DEBUG, "quic: version negotiation for 0x%x", vc.version);
		}
		return;
	}
	if (rv != 0) {
		drop(ep, len, "not a QUIC packet");
		return;
	}
	struct sockaddr_storage ls, rs;
	const bst_sockaddr *local = dst != NULL && dst->ip.family != 0 ? dst : &ep->cfg.local;
	bst_sockaddr local_port = *local;
	local_port.port = ep->cfg.local.port; /* IP_PKTINFO gives the address, not the port */
	socklen_t ll = bst_quic_sockaddr(&local_port, &ls), rl = bst_quic_sockaddr(src, &rs);
	if (ll == 0 || rl == 0)
		return;
	ngtcp2_path path = { { (ngtcp2_sockaddr *)&ls, ll }, { (ngtcp2_sockaddr *)&rs, rl }, NULL };
	bst_quic_conn *c = cid_find(ep, vc.dcid, vc.dcidlen);
	if (c == NULL) {
		unknown(ep, data, len, &vc, src, &local_port, &path, ecn);
		return;
	}
	c->rx_pkts++;
	if (c->draining)
		return;
	if (c->closing) { /* repeat the close (RFC 9000 section 10.2.1) */
		send_raw(ep, c->close_pkt, c->close_len, src, &local_port);
		return;
	}
	ngtcp2_pkt_info pi = { .ecn = ecn };
	ERR_clear_error();
	rv = ngtcp2_conn_read_pkt(c->q, &path, &pi, data, len, now_ns());
	if (rv == NGTCP2_ERR_DRAINING) {
		c->draining = true;
		arm(c, now_ns());
		return;
	}
	if (rv == NGTCP2_ERR_DROP_CONN || rv == NGTCP2_ERR_RETRY) {
		conn_free(c);
		return;
	}
	if (rv != 0) {
		conn_fail(c, rv);
		return;
	}
	conn_write(c);
}

/* ---- the endpoint ---- */

bst_quic_endpoint *bst_quic_endpoint_new(const bst_quic_ep_cfg *cfg, bst_err *err)
{
	if (cfg->q == NULL || cfg->q->ssl_ctx == NULL || cfg->q->nversions == 0) {
		bst_err_set(err, "quic: no TLS context for the listener");
		return NULL;
	}
	bst_quic_endpoint *ep = calloc(1, sizeof *ep);
	if (ep == NULL) {
		bst_err_set(err, "quic: out of memory");
		return NULL;
	}
	ep->cfg = *cfg;
	ep->q = *cfg->q;
	ep->cfg.q = &ep->q;
	ep->nbuckets = 256;
	ep->buckets = calloc(ep->nbuckets, sizeof *ep->buckets);
	ep->pool = malloc(BST_QUIC_TXQ * sizeof *ep->pool);
	if (ep->buckets == NULL || ep->pool == NULL ||
	    getrandom(ep->hkey, sizeof ep->hkey, 0) != (ssize_t)sizeof ep->hkey) {
		bst_err_set(err, "quic: out of memory");
		free(ep->buckets);
		free(ep->pool);
		free(ep);
		return NULL;
	}
	return ep;
}

void bst_quic_endpoint_free(bst_quic_endpoint *ep)
{
	if (ep == NULL)
		return;
	ep->cfg.worker = NULL; /* teardown is not a stream of closes */
	while (ep->conns != NULL)
		conn_free(ep->conns);
	free(ep->buckets);
	free(ep->pool);
	memset(&ep->cfg.secrets, 0, sizeof ep->cfg.secrets);
	free(ep);
}

void bst_quic_endpoint_stats(const bst_quic_endpoint *ep, bst_quic_stats *out)
{
	*out = ep->st;
}

static void on_recv(void *ud, bst_udp_msg *msgs, int n, int err)
{
	bst_quic_endpoint *ep = ud;
	if (err < 0) {
		bst_log(BST_LOG_ERROR, "quic: receive stopped: %s", strerror(-err));
		if (!ep->draining && bst_udp_start(ep->sock, NULL, on_recv, ep) != 0)
			bst_log(BST_LOG_ERROR, "quic: cannot restart receiving");
		return;
	}
	for (int i = 0; i < n; i++) {
		size_t off = 0, sl;
		const unsigned char *seg;
		while ((sl = bst_udp_segment(&msgs[i], &off, &seg)) > 0)
			bst_quic_endpoint_input(ep, seg, sl, &msgs[i].src, &msgs[i].dst, msgs[i].ecn);
		bst_buf_unref(msgs[i].buf);
	}
}

bst_quic_endpoint *bst_quic_endpoint_start(bst_worker *w, bst_sock *s, const bst_listener_set *set,
					   const bst_cfg_quic *q, bst_err *err)
{
	bst_quic_ep_cfg cfg;
	memset(&cfg, 0, sizeof cfg);
	cfg.loop = bst_worker_loop(w);
	cfg.q = q;
	cfg.set = set;
	cfg.slot = (uint16_t)bst_worker_slot(w);
	cfg.worker = w;
	unsigned char sec[BST_QUIC_SECRETS_LEN];
	if (bst_tickets_quic_secrets(sec) != 0) {
		bst_err_set(err, "quic: no token secrets (the tickets region is missing)");
		return NULL;
	}
	memcpy(cfg.secrets.token, sec, BST_TOKEN_SECRET_LEN);
	memcpy(cfg.secrets.reset, sec + BST_TOKEN_SECRET_LEN, BST_TOKEN_SECRET_LEN);
	memset(sec, 0, sizeof sec);
	struct sockaddr_storage ss;
	socklen_t sl = sizeof ss;
	if (getsockname(bst_sock_fd(s), (struct sockaddr *)&ss, &sl) != 0 ||
	    !from_sockaddr((const ngtcp2_sockaddr *)&ss, &cfg.local)) {
		bst_err_set(err, "quic: getsockname: %s", strerror(errno));
		return NULL;
	}
	bst_quic_endpoint *ep = bst_quic_endpoint_new(&cfg, err);
	if (ep == NULL)
		return NULL;
	ep->sock = s;
	/* Task 5 registers quic_gso, quic_gro and rcvbuf; until then the mechanism's defaults. */
	bst_udp_cfg uc = { .gso = true, .gro = true, .rcvbuf = 0, .max_dgram = 0 };
	int rc = bst_udp_start(s, &uc, on_recv, ep);
	if (rc != 0) {
		bst_err_set(err, "quic: cannot receive on the UDP socket: %s", strerror(-rc));
		bst_quic_endpoint_free(ep);
		return NULL;
	}
	bst_udp_stats us;
	bst_udp_stats_get(s, &us);
	if (!us.ring)
		bst_log(BST_LOG_INFO, "quic: UDP on port %u runs on the readiness path (recvmmsg): %s",
			(unsigned)cfg.local.port,
			bst_loop_backend(cfg.loop) != BST_BACKEND_URING
				? "the epoll backend"
				: "no io_uring UDP buffers, or a kernel without multishot RECVMSG");
	return ep;
}

static void close_all(bst_quic_endpoint *ep)
{
	ngtcp2_ccerr err;
	ngtcp2_ccerr_default(&err);
	ngtcp2_ccerr_set_application_error(&err, 0x100 /* H3_NO_ERROR */, NULL, 0);
	bst_quic_conn *next;
	for (bst_quic_conn *c = ep->conns; c != NULL; c = next) {
		next = c->next;
		if (c->closing || c->draining)
			continue;
		if (c->h3 != NULL) /* GOAWAY: the requests in flight finish, then the connection closes */
			bst_h3_drain(c->h3);
		else
			conn_close(c, &err); /* may free c: next was read first */
	}
}

void bst_quic_endpoint_drain(bst_quic_endpoint *ep)
{
	if (ep == NULL || ep->draining)
		return;
	ep->draining = true;
	close_all(ep);
	/* An HTTP/3 connection finishing its requests after GOAWAY still needs the client's ACKs and
	 * credit: receiving goes on until the process exits (a new connection's Initial is dropped,
	 * see unknown()). Without one, nothing more is read. */
	bool finishing = false;
	for (bst_quic_conn *c = ep->conns; c != NULL; c = c->next)
		finishing |= c->h3 != NULL && !c->closing && !c->draining;
	if (ep->sock != NULL && !finishing)
		(void)bst_udp_stop(ep->sock);
}

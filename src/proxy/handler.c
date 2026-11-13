/* See handler.h. One exchange per request: pick a peer, get a connection from the pool, write the
 * regenerated head, stream the request body with credit, read the response with the strict
 * reader and stream it to the client one send at a time (the upstream is not read while a send
 * to the client is in flight, so a slow client slows the upstream and memory stays bounded).
 *
 * Lifetime. The exchange state (pctx) is malloc'd, not taken from the stream arena: upstream
 * callbacks may still be queued when the stream goes. The stream's hctx points at a small
 * arena shell that holds the pctx pointer and the $upstream_* values. The pctx is freed when
 * the exchange is over (the response finished or the stream was reset); a busy count defers
 * that to the outermost callback, so no callback touches freed memory. */
#include "proxy/handler.h"
#include "proxy/proxyproto.h"
#include "http/transport.h"

#include "core/log.h"
#include "proc/worker.h"
#include "proxy/balance.h"
#include "proxy/breaker.h"
#include "proxy/client_h1.h"
#include "proxy/client_h2.h"
#include "proxy/pool.h"
#include "proxy/retry.h"
#include "proxy/spool.h"
#include "proxy/tunnel.h"
#include "proxy/upstream.h"
#include "route/vars.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct pctx pctx;

typedef struct shell {
	pctx *p;
	char addr[BST_ADDR_STRLEN + 8]; /* $upstream_addr */
	int status;			/* $upstream_status */
	uint64_t ms;			/* $upstream_response_time */
	bool has_time;
} shell;

struct pctx {
	bst_stream *s; /* NULL once the stream ended */
	shell *sh;
	const bst_cfg_proxy *pc;
	const bst_cfg_upstream *up;
	bst_loop *loop;
	bst_upconn *uc;
	const bst_peer *peer;
	bst_sockaddr addr;
	bool reused;
	unsigned attempts;
	unsigned busy;
	bool dead;
	bst_buf *head; /* the request head, kept for a retry */
	/* request body */
	bool req_body, req_chunked, req_done, body_started, body_sent;
	bst_chain sendq, pend;
	bool sending;
	/* response */
	bst_h1_client rc;
	bool rc_init;
	bool head_sent;
	bst_chain cpend;
	bool cend, csending;
	bool recv_on;
	bst_timer rtm, wtm;
	uint64_t t0;
	/* resilience (Task 5) */
	bst_breaker *brk;
	bool brk_counted, brk_pending, brk_probe, brk_retry, answered_ok;
	const bst_peer *tried[16];
	size_t ntried;
	unsigned retries;
	/* tunnels (Task 7) */
	bool ws;       /* a WebSocket upgrade was passed on */
	bool tunnel;   /* the upstream said 101: raw bytes both ways */
	bool tun_slot; /* holds one of max_tunnels */
	bool up_shut;  /* the upstream's write side was shut (the client half-closed) */
	bool ws_ext;   /* an extended CONNECT (RFC 8441, RFC 9220) sent on as an HTTP/1.1 Upgrade */
	char ws_key[32]; /* the Sec-WebSocket-Key we made for it */
	bst_timer tidle, tmax;
	/* HTTP/2 upstreams (Task 8) */
	bst_h2us *hs;	    /* the upstream stream of this request */
	bst_headers h2req;  /* pseudo-fields, then the regular fields */
	size_t h2_unacked;  /* body bytes received and not yet reported consumed */
	unsigned h2_refused; /* reopened after the peer refused the stream */
	bool grpc;	    /* Content-Type application/grpc: failures become a grpc-status */
	bool has_tr;	    /* response trailers to pass on */
	bst_headers tr;
	/* buffering (Task 10, proxy/spool.h) */
	bst_spool *rqs;	     /* request_buffering: the whole body, then the exchange */
	bst_headers rq_hs;   /* the request fields, kept to write the head again with a length */
	bst_h1_req_out ro;
	uint64_t rq_pos;     /* next spool byte to send in this exchange */
	unsigned rq_epoch;   /* bumped per exchange: a read of an earlier one is dropped */
	unsigned rq_rd_epoch;
	bool rq_reading;
	bool rs_on;	     /* response_buffering */
	bst_spool *rss;	     /* the response body, read at the upstream's pace */
	uint64_t rs_pos;     /* next spool byte to give the client */
	bool rs_reading;
};

#define MAX_TRIED (sizeof ((pctx *)0)->tried / sizeof ((pctx *)0)->tried[0])

/* The breaker's books for this request, once. */
static void brk_settle(pctx *p)
{
	if (p->brk_retry)
		bst_breaker_retry_done(p->brk);
	p->brk_retry = false;
	if (!p->brk_counted)
		return;
	p->brk_counted = false;
	bst_breaker_done(p->brk, p->brk_pending, p->answered_ok, p->brk_probe,
			 bst_loop_now_ms(p->loop));
}

static void destroy(pctx *p)
{
	bst_timer_cancel(&p->rtm);
	bst_timer_cancel(&p->wtm);
	bst_timer_cancel(&p->tidle);
	bst_timer_cancel(&p->tmax);
	if (p->tun_slot)
		bst_tunnel_release();
	if (p->uc != NULL)
		bst_pool_close(p->uc); /* never back to the pool from here: it may be mid-exchange */
	bst_h2us_release(p->hs); /* an open stream is cancelled */
	bst_chain_clear(&p->sendq);
	bst_chain_clear(&p->pend);
	bst_chain_clear(&p->cpend);
	bst_buf_unref(p->head);
	if (p->rc_init)
		bst_h1_client_free(&p->rc);
	bst_spool_close(p->rqs); /* a read still on the aio pool is dropped */
	bst_spool_close(p->rss);
	free(p);
}

static void enter(pctx *p)
{
	p->busy++;
}

static void leave(pctx *p)
{
	if (--p->busy == 0 && p->dead)
		destroy(p);
}

/* The stream is no longer ours: forget it, so nothing touches it again. */
static void detach(pctx *p)
{
	brk_settle(p);
	if (p->sh != NULL)
		p->sh->p = NULL;
	p->sh = NULL;
	p->s = NULL;
	p->dead = true;
}

static void note_time(pctx *p)
{
	if (p->sh != NULL && !p->sh->has_time) {
		p->sh->ms = bst_loop_now_ms(p->loop) - p->t0;
		p->sh->has_time = true;
	}
}

/* A gRPC client is told of a failure in its own terms: a trailers-only response with the
 * grpc-status the HTTP status maps to (UNAVAILABLE for 502 and 503, DEADLINE_EXCEEDED for 504). */
static void grpc_error(bst_stream *s, int status)
{
	int code = status == 504 ? 4 : status == 502 || status == 503 ? 14 : status == 429 ? 8 : 13;
	const char *msg = code == 4 ? "upstream timed out" : code == 14 ? "upstream unavailable"
					: code == 8 ? "resource exhausted" : "proxy error";
	char cs[8];
	int n = snprintf(cs, sizeof cs, "%d", code);
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = 200;
	h.content_length = -1;
	bst_headers_init(&h.headers, s->arena);
	if (bst_headers_add(&h.headers, BST_S("content-type"), BST_S("application/grpc")) != 0 ||
	    bst_headers_add(&h.headers, BST_S("grpc-status"),
			    (bst_str){ cs, n > 0 ? (uint32_t)n : 0 }) != 0 ||
	    bst_headers_add(&h.headers, BST_S("grpc-message"),
			    (bst_str){ msg, (uint32_t)strlen(msg) }) != 0) {
		(void)bst_send_error(s, status);
		return;
	}
	(void)bst_stream_send_head(s, &h, true);
}

/* Before any response byte reached the client: an error page. After: abort the stream. */
static void fail(pctx *p, int status)
{
	bst_stream *s = p->s;
	if (s == NULL)
		return;
	note_time(p);
	if (p->uc != NULL) {
		bst_pool_close(p->uc);
		p->uc = NULL;
	}
	bst_h2us_release(p->hs);
	p->hs = NULL;
	bool sent = p->head_sent, grpc = p->grpc;
	detach(p);
	if (!sent && grpc)
		grpc_error(s, status);
	else if (!sent)
		(void)bst_send_error(s, status);
	else
		s->ops->reset(s, BST_STREAM_ERR_INTERNAL); /* never a clean end of a cut response */
}

/* 503 with Retry-After, before anything went upstream. */
static void unavailable(pctx *p, unsigned secs)
{
	bst_stream *s = p->s;
	if (s == NULL)
		return;
	note_time(p);
	bool grpc = p->grpc;
	detach(p);
	if (grpc) {
		grpc_error(s, 503);
		return;
	}
	char v[16];
	int n = snprintf(v, sizeof v, "%u", secs ? secs : 1);
	(void)bst_send_error_hdr(s, 503, BST_S("Retry-After"),
				 (bst_str){ v, n > 0 ? (uint32_t)n : 0 });
}

static void start_connect(pctx *p, bool fresh);

static bool idempotent(bst_method m)
{
	return m == BST_M_GET || m == BST_M_HEAD || m == BST_M_OPTIONS || m == BST_M_PUT ||
	       m == BST_M_DELETE || m == BST_M_TRACE;
}

/* Drops the current upstream exchange so the request can start over. */
static void reset_exchange(pctx *p)
{
	if (p->uc != NULL)
		bst_pool_close(p->uc);
	p->uc = NULL;
	bst_h2us_release(p->hs);
	p->hs = NULL;
	p->h2_unacked = 0;
	bst_timer_cancel(&p->rtm);
	bst_timer_cancel(&p->wtm);
	bst_chain_clear(&p->sendq);
	bst_chain_clear(&p->pend);
	p->sending = false;
	p->recv_on = false;
	if (p->rc_init)
		bst_h1_client_free(&p->rc);
	p->rc_init = false;
}

static void set_addr_var(pctx *p)
{
	char a[BST_ADDR_STRLEN];
	bst_addr_format(&p->addr.ip, a, sizeof a);
	snprintf(p->sh->addr, sizeof p->sh->addr, p->addr.ip.family == BST_IP_V6 ? "[%s]:%u" : "%s:%u",
		 a, p->addr.port);
}

/* A failure of a real request counts toward passive ejection. */
static void passive_fail(pctx *p)
{
	if (p->peer != NULL && bst_peer_passive_fail(p->peer, &p->up->passive, bst_mono_ms()))
		bst_log(BST_LOG_WARN, "proxy: upstream %s: server %s ejected for %llu ms after %u "
				      "failures", p->up->name, p->sh->addr,
			(unsigned long long)p->up->passive.for_ms, p->up->passive.fails);
}

/* Tries the request again on a peer it has not tried, when `retry` allows it: the kind of failure
 * is in `on`, nothing reached the client, and either nothing reached the upstream (connect) or
 * the request is idempotent with no body. True when a new try started. */
static bool retry_other(pctx *p, unsigned kind, bool connect_level)
{
	const bst_up_retry *r = &p->up->retry;
	bst_stream *s = p->s;
	if (s == NULL || p->head_sent || (r->on & kind) == 0 || p->retries >= r->attempts)
		return false;
	bool replayable = p->rqs != NULL && p->pc->retry_buffered; /* the whole body is at hand */
	if (!connect_level && (!idempotent(s->req.head.method) || p->req_body) && !replayable)
		return false; /* bytes of a request that may not be repeated reached the upstream */
	if (r->timeout_ms != 0 && bst_loop_now_ms(p->loop) - p->t0 >= r->timeout_ms)
		return false;
	if (p->ntried < MAX_TRIED)
		p->tried[p->ntried++] = p->peer;
	bst_pick_ctx pk = { .s = s, .avoid = p->tried, .navoid = p->ntried };
	bst_sockaddr addr;
	const bst_peer *np = bst_balance_pick(p->up, &pk, &addr);
	if (np == NULL)
		return false;
	if (!bst_retry_take(p->up)) {
		bst_log(BST_LOG_WARN, "proxy: upstream %s: retry budget spent: not retrying",
			p->up->name);
		return false;
	}
	if (!p->brk_retry && p->brk != NULL) {
		if (!bst_breaker_retry(p->brk))
			return false;
		p->brk_retry = true;
	}
	p->retries++;
	bst_log(BST_LOG_INFO, "proxy: upstream %s: retrying on another server after %s from %s",
		p->up->name, kind == BST_RETRY_ON_TIMEOUT ? "a timeout"
			     : kind == BST_RETRY_ON_5XX	   ? "a 5xx"
							   : "an error",
		p->sh->addr);
	reset_exchange(p);
	p->peer = np;
	p->addr = addr;
	set_addr_var(p);
	p->body_started = false;
	start_connect(p, false);
	return true;
}

/* An upstream failure: retried on a fresh connection when that is safe, else fail. */
static void upstream_error(pctx *p, int err)
{
	if (p->s == NULL)
		return;
	bool none_back = !p->rc_init || !p->rc.got_bytes;
	if (p->reused && none_back && !p->body_started && !p->head_sent && p->attempts < 2 &&
	    idempotent(p->s->req.head.method) && err != -ETIMEDOUT) {
		/* a pooled connection the upstream closed just as we wrote: try once more */
		bst_log(BST_LOG_INFO, "proxy: a reused connection to %s failed (%s): retrying on a "
				      "fresh one", p->sh->addr, strerror(-err));
		reset_exchange(p);
		start_connect(p, true);
		return;
	}
	if (!p->head_sent) {
		passive_fail(p);
		if (retry_other(p, err == -ETIMEDOUT ? BST_RETRY_ON_TIMEOUT : BST_RETRY_ON_ERROR,
				false))
			return;
	}
	bst_log(BST_LOG_WARN, "proxy: upstream %s: %s%s", p->sh->addr,
		err == -ETIMEDOUT ? "timed out" : strerror(-err),
		p->head_sent ? " after the response started: aborting the client's stream" : "");
	fail(p, err == -ETIMEDOUT ? 504 : 502);
}

/* ---- to the client ---- */

static void pump(pctx *p);

static void client_done(void *ud, size_t bytes, int err)
{
	pctx *p = ud;
	(void)bytes;
	enter(p);
	p->csending = false;
	if (err == 0 && p->s != NULL)
		pump(p);
	leave(p);
}

static void on_up_recv(void *ud, bst_buf *b, int err);
static void on_read_timeout(void *ud);

static void resume_upstream(pctx *p)
{
	if (p->hs != NULL && !p->csending && p->s != NULL) {
		/* the client took what came: the upstream stream may send that much more */
		if (p->h2_unacked > 0)
			bst_h2us_consumed(p->hs, p->h2_unacked);
		p->h2_unacked = 0;
		bst_loop_timer_arm(p->loop, &p->rtm, p->up->read_timeout_ms, on_read_timeout, p);
		return;
	}
	if (p->uc == NULL || p->recv_on || p->csending || p->s == NULL)
		return;
	if (bst_upconn_recv_start(p->uc, on_up_recv, p) != 0) {
		upstream_error(p, -EIO);
		return;
	}
	p->recv_on = true;
	if (!p->tunnel) /* a tunnel has its idle timer instead */
		bst_loop_timer_arm(p->loop, &p->rtm, p->up->read_timeout_ms, on_read_timeout, p);
}

/* Sends what is waiting; the last send carries end_stream and no callback, and ends the
 * exchange on our side. */
static void rs_feed(pctx *p);

static void pump(pctx *p)
{
	if (p->csending || p->s == NULL || p->rs_reading)
		return;
	bool spooled = p->rss != NULL && p->rs_pos < bst_spool_size(p->rss); /* more to give */
	if (spooled && bst_chain_len(&p->cpend) == 0) {
		rs_feed(p); /* the client is ready: its next part from the spool */
		return;
	}
	if (bst_chain_len(&p->cpend) == 0 && !p->cend) {
		resume_upstream(p);
		return;
	}
	bst_stream *s = p->s;
	if (p->cend && !spooled) {
		note_time(p);
		bool tr = p->has_tr && p->tr.n > 0;
		detach(p);
		if (tr) {
			/* the body, then the trailers end the response */
			if (bst_chain_len(&p->cpend) > 0)
				(void)bst_stream_send_body(s, &p->cpend, false, NULL, NULL);
			if (bst_stream_send_trailers(s, &p->tr) == 0)
				return;
			/* a protocol that can not carry them (HTTP/1.1 with a length) ends cleanly */
		}
		(void)bst_stream_send_body(s, &p->cpend, true, NULL, NULL);
		return;
	}
	p->csending = true;
	if (bst_stream_send_body(s, &p->cpend, false, client_done, p) != 0) {
		p->csending = false; /* the stream is gone: on_reset follows or already ran */
	}
}

static void rs_got(pctx *p, bst_buf *b)
{
	p->rs_pos += b->len;
	int rc = bst_chain_add_mem(&p->cpend, b, 0, b->len);
	bst_buf_unref(b);
	if (rc != 0) {
		fail(p, 502);
		return;
	}
	pump(p);
}

static void rs_read_done(void *ud, bst_buf *b, int err)
{
	pctx *p = ud;
	enter(p);
	p->rs_reading = false;
	if (p->s == NULL) {
		bst_buf_unref(b);
	} else if (b == NULL) {
		bst_log(BST_LOG_ERROR, "proxy: reading the spooled response failed: %s", strerror(-err));
		fail(p, 502);
	} else {
		rs_got(p, b);
	}
	leave(p);
}

static void rs_feed(pctx *p)
{
	bst_buf *b = NULL;
	int rc = bst_spool_read(p->rss, p->rs_pos, p->pc->buffer_size, &b, rs_read_done, p);
	if (rc == 1) {
		rs_got(p, b);
	} else if (rc == 0) {
		p->rs_reading = true;
	} else {
		bst_log(BST_LOG_ERROR, "proxy: reading the spooled response failed: %s", strerror(-rc));
		fail(p, 502);
	}
}

/* The upstream's part is over: keep the connection when it may carry another exchange. */
static void finish_upstream(pctx *p, bool reusable)
{
	bst_timer_cancel(&p->rtm);
	bst_timer_cancel(&p->wtm);
	bst_h2us_release(p->hs); /* a complete stream is already closed; else it is cancelled */
	p->hs = NULL;
	if (p->uc == NULL)
		return;
	if (p->recv_on)
		bst_upconn_recv_stop(p->uc);
	p->recv_on = false;
	bool clean = reusable && !p->sending && bst_chain_len(&p->sendq) == 0 &&
		     bst_chain_len(&p->pend) == 0 && (!p->req_body || p->req_done);
	if (clean)
		bst_pool_put(p->uc);
	else
		bst_pool_close(p->uc);
	p->uc = NULL;
}

/* ---- the response ---- */

/* The final response head: status, the upstream's fields uh, clen (or -1) and whether a body
 * follows. reusable: the upstream connection may carry another exchange once this one ends.
 * 0 when the body follows; -1 when the exchange went elsewhere (ended, retried or failed). */
static int send_head_of(pctx *p, int status, const bst_headers *uh, int64_t clen, bool end,
			bool reusable)
{
	bst_stream *s = p->s;
	p->sh->status = status;
	if (status >= 500) {
		passive_fail(p);
		int st = status;
		if ((st == 502 || st == 503 || st == 504) && retry_other(p, BST_RETRY_ON_5XX, false))
			return -1;
	} else {
		p->answered_ok = true;
	}
	if (p->brk_counted && p->brk_pending) {
		bst_breaker_answered(p->brk);
		p->brk_pending = false;
	}
	uint64_t now = bst_loop_now_ms(p->loop);
	bst_balance_observe(p->up, p->peer, now - p->t0, now); /* peak_ewma */
	if (p->pc->intercept_errors && status >= 400) {
		finish_upstream(p, false);
		note_time(p);
		detach(p);
		(void)bst_send_error(s, status); /* error_page applies */
		return -1;
	}
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = status;
	h.content_length = clen;
	bst_headers_init(&h.headers, s->arena);
	if (bst_proxy_resp_headers(s, uh, &h.headers) != 0) {
		fail(p, 502);
		return -1;
	}
	if (s->req.head.method == BST_M_HEAD) {
		const bst_header *cl = bst_headers_get(uh, BST_H_CONTENT_LENGTH);
		uint64_t v;
		if (cl != NULL && bst_str_to_u64(cl->value, &v))
			h.content_length = (int64_t)v; /* what a GET would have had */
	}
	p->head_sent = true;
	if (end) {
		finish_upstream(p, reusable);
		note_time(p);
		detach(p);
		(void)bst_stream_send_head(s, &h, true);
		return -1;
	}
	if (bst_stream_send_head(s, &h, false) != 0) {
		fail(p, 502);
		return -1;
	}
	return 0;
}

static int send_head(pctx *p)
{
	const bst_h1_client *rc = &p->rc;
	bool end = rc->fr.kind == BST_RESP_BODY_NONE ||
		   (rc->fr.kind == BST_RESP_BODY_LENGTH && rc->fr.length == 0);
	return send_head_of(p, rc->head.status, &rc->head.headers,
			    rc->fr.kind == BST_RESP_BODY_LENGTH ? (int64_t)rc->fr.length : -1, end,
			    bst_h1_client_reusable(rc));
}

static void send_interim(pctx *p)
{
	int st = p->rc.head.status;
	if (st == 100 || p->head_sent)
		return; /* our own 100 went out when the body was asked for */
	bst_headers hs;
	bst_headers_init(&hs, p->s->arena);
	if (bst_proxy_resp_headers(p->s, &p->rc.head.headers, &hs) == 0)
		(void)bst_stream_send_interim(p->s, st, &hs);
}

static void on_read_timeout(void *ud)
{
	pctx *p = ud;
	enter(p);
	upstream_error(p, -ETIMEDOUT);
	leave(p);
}

/* ---- tunnels ---- */

static void tunnel_touch(pctx *p);

static void on_tunnel_timeout(void *ud)
{
	pctx *p = ud;
	enter(p);
	bst_log(BST_LOG_INFO, "proxy: tunnel to %s closed: %s", p->sh != NULL ? p->sh->addr : "?",
		"timed out");
	fail(p, 504);
	leave(p);
}

static void tunnel_touch(pctx *p)
{
	if (p->tunnel && p->s != NULL)
		bst_loop_timer_arm(p->loop, &p->tidle, p->pc->tunnel_idle_ms, on_tunnel_timeout, p);
}

/* The client ended its direction and everything it sent reached the upstream: pass the
 * half-close on, and give the upstream tunnel_drain_timeout to finish. */
static void tunnel_half_close(pctx *p)
{
	if (!p->tunnel || p->up_shut || !p->req_done || p->sending || bst_chain_len(&p->pend) > 0 ||
	    bst_chain_len(&p->sendq) > 0 || p->uc == NULL)
		return;
	p->up_shut = true;
	if (p->uc->tls == NULL)
		(void)bst_sock_shutdown_wr(p->uc->sk);
	bst_loop_timer_arm(p->loop, &p->tmax, p->pc->tunnel_drain_ms, on_tunnel_timeout, p);
}

/* The upstream answered 101: the tunnel opens when we asked for it, else it is refused. */
static void tunnel_start(pctx *p, bst_buf *b, size_t off)
{
	bst_stream *s = p->s;
	const bst_headers *uh = &p->rc.head.headers;
	if (!p->ws || !bst_headers_list_has(uh, BST_H_UPGRADE, BST_S("websocket"))) {
		bst_log(BST_LOG_WARN, "proxy: upstream %s answered 101 to a request that did not ask "
				      "for that upgrade: 502", p->sh->addr);
		fail(p, 502);
		return;
	}
	p->sh->status = 101;
	p->answered_ok = true;
	if (p->brk_counted && p->brk_pending) {
		bst_breaker_answered(p->brk);
		p->brk_pending = false;
	}
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = 101;
	h.content_length = -1;
	bst_headers_init(&h.headers, s->arena);
	if (p->ws_ext) {
		/* RFC 8441 section 5: the HTTP/2 or HTTP/3 client gets a 2xx and no key exchange; the
		 * upstream's accept must match the key we sent, or it is not a WebSocket server */
		const bst_header *acc = bst_headers_get_name(uh, BST_S("sec-websocket-accept"));
		if (acc == NULL || !bst_tunnel_accept_ok(p->ws_key, acc->value)) {
			bst_log(BST_LOG_WARN, "proxy: upstream %s answered 101 with a wrong "
					      "Sec-WebSocket-Accept: 502", p->sh->addr);
			fail(p, 502);
			return;
		}
		h.status = 200;
		if (bst_proxy_resp_headers(s, uh, &h.headers) != 0) {
			fail(p, 502);
			return;
		}
		(void)bst_headers_remove_name(&h.headers, BST_S("sec-websocket-accept"));
	} else if (bst_proxy_resp_headers(s, uh, &h.headers) != 0 ||
		   bst_headers_add(&h.headers, BST_S("Upgrade"), BST_S("websocket")) != 0 ||
		   bst_headers_add(&h.headers, BST_S("Connection"), BST_S("Upgrade")) != 0) {
		fail(p, 502);
		return;
	}
	bst_timer_cancel(&p->rtm);
	if (bst_stream_send_head(s, &h, false) != 0) {
		fail(p, 502);
		return;
	}
	p->head_sent = true;
	p->tunnel = true;
	if (off < b->len && bst_chain_add_mem(&p->cpend, b, off, b->len - off) != 0) {
		fail(p, 502);
		return;
	}
	p->req_body = true;
	p->req_chunked = false;
	p->req_done = false;
	p->body_started = true;
	bst_loop_timer_arm(p->loop, &p->tmax, p->pc->tunnel_max_ms, on_tunnel_timeout, p);
	tunnel_touch(p);
	bst_stream_read_body(s, p->pc->buffer_size);
	if (p->s != NULL)
		pump(p);
}

static void on_up_recv(void *ud, bst_buf *b, int err)
{
	pctx *p = ud;
	enter(p);
	if (p->s == NULL)
		goto out;
	if (p->tunnel && b != NULL) {
		tunnel_touch(p);
		if (bst_chain_add_mem(&p->cpend, b, 0, b->len) != 0) {
			fail(p, 502);
			goto out;
		}
		pump(p);
		if (p->s != NULL && p->csending && p->recv_on && p->uc != NULL) {
			bst_upconn_recv_stop(p->uc); /* backpressure */
			p->recv_on = false;
		}
		goto out;
	}
	if (p->tunnel && b == NULL && err == 0) { /* the upstream ended: the tunnel's end */
		p->recv_on = false;
		finish_upstream(p, false);
		p->cend = true;
		pump(p);
		goto out;
	}
	if (b == NULL) {
		p->recv_on = false;
		if (err == 0 && bst_h1_client_eof(&p->rc) == BST_UPC_DONE) {
			finish_upstream(p, false);
			p->cend = true;
			pump(p);
		} else {
			upstream_error(p, err != 0 ? err : -ECONNRESET);
		}
		goto out;
	}
	bst_loop_timer_arm(p->loop, &p->rtm, p->up->read_timeout_ms, on_read_timeout, p);
	size_t off = 0;
	bst_chain body;
	bst_chain_init(&body, p->s->chain_slab);
	for (;;) {
		bst_upc_ev ev = bst_h1_client_feed(&p->rc, b, &off, &body);
		if (ev == BST_UPC_INTERIM) {
			send_interim(p);
			continue;
		}
		if (ev == BST_UPC_HEAD) {
			if (p->rc.head.status == 101) {
				tunnel_start(p, b, off);
				break;
			}
			if (send_head(p) != 0)
				break;
			continue;
		}
		if (ev == BST_UPC_BODY || ev == BST_UPC_MORE || ev == BST_UPC_DONE) {
			if (p->rs_on && bst_chain_len(&body) > 0) { /* response_buffering: to the spool */
				if (p->rss == NULL)
					p->rss = bst_spool_open(p->s->worker, p->pc->spool_mem);
				int wr = p->rss == NULL ? -ENOMEM : bst_spool_write(p->rss, &body);
				if (wr != 0) {
					bst_log(BST_LOG_ERROR, "proxy: spooling the response of %s failed: %s",
						p->sh->addr, strerror(-wr));
					fail(p, 502);
					break;
				}
			}
			if (bst_chain_len(&body) > 0 && bst_chain_move(&p->cpend, &body) != 0) {
				fail(p, 502);
				break;
			}
			if (ev == BST_UPC_BODY)
				continue;
			if (ev == BST_UPC_DONE) {
				finish_upstream(p, bst_h1_client_reusable(&p->rc) && off == b->len);
				p->cend = true;
			}
			pump(p);
			if (p->s != NULL && p->csending && p->recv_on && p->uc != NULL && !p->rs_on) {
				bst_upconn_recv_stop(p->uc); /* backpressure: resume when the client took it */
				bst_timer_cancel(&p->rtm);
				p->recv_on = false;
			}
			break;
		}
		/* ERROR */
		bst_log(BST_LOG_WARN, "proxy: upstream %s sent a malformed response", p->sh->addr);
		upstream_error(p, -EPROTO);
		break;
	}
	bst_chain_clear(&body);
out:
	bst_buf_unref(b);
	leave(p);
}

/* ---- the request ---- */

static void kick_send(pctx *p);
static void rq_feed(pctx *p);

/* request_buffering: the spooled body goes out a buffer_size at a time, each when the last one
 * reached the upstream. */
static void rq_got(pctx *p, bst_buf *b)
{
	p->rq_pos += b->len;
	int rc = bst_chain_add_mem(&p->pend, b, 0, b->len);
	bst_buf_unref(b);
	if (rc != 0) {
		fail(p, 500);
		return;
	}
	kick_send(p);
}

static void rq_read_done(void *ud, bst_buf *b, int err)
{
	pctx *p = ud;
	enter(p);
	p->rq_reading = false;
	if (p->s == NULL || p->rq_rd_epoch != p->rq_epoch || p->uc == NULL) {
		bst_buf_unref(b); /* the request ended, or this exchange was dropped for a retry */
		if (p->s != NULL && p->uc != NULL && p->rq_rd_epoch != p->rq_epoch)
			rq_feed(p);
	} else if (b == NULL) {
		bst_log(BST_LOG_ERROR, "proxy: reading the spooled request body failed: %s", strerror(-err));
		fail(p, 500);
	} else {
		rq_got(p, b);
	}
	leave(p);
}

static void rq_feed(pctx *p)
{
	if (p->rq_reading || p->rq_pos >= bst_spool_size(p->rqs))
		return;
	bst_buf *b = NULL;
	int rc = bst_spool_read(p->rqs, p->rq_pos, p->pc->buffer_size, &b, rq_read_done, p);
	if (rc == 1) {
		rq_got(p, b);
	} else if (rc == 0) {
		p->rq_reading = true;
		p->rq_rd_epoch = p->rq_epoch;
	} else {
		bst_log(BST_LOG_ERROR, "proxy: reading the spooled request body failed: %s", strerror(-rc));
		fail(p, 500);
	}
}

static void on_write_timeout(void *ud)
{
	pctx *p = ud;
	enter(p);
	upstream_error(p, -ETIMEDOUT);
	leave(p);
}

static void on_sent(void *ud, size_t bytes, int err)
{
	pctx *p = ud;
	(void)bytes;
	enter(p);
	p->sending = false;
	bst_timer_cancel(&p->wtm);
	if (p->s == NULL || p->uc == NULL)
		goto out;
	if (err != 0) {
		upstream_error(p, err);
		goto out;
	}
	if (bst_chain_len(&p->pend) > 0) {
		kick_send(p);
	} else if (p->rqs != NULL && p->rq_pos < bst_spool_size(p->rqs)) {
		rq_feed(p);
	} else if (p->req_body && !p->req_done && p->body_started) {
		bst_stream_read_body(p->s, p->pc->buffer_size); /* the next round of credit */
	} else {
		tunnel_half_close(p);
	}
out:
	leave(p);
}

static void kick_send(pctx *p)
{
	if (p->sending || p->uc == NULL)
		return;
	if (bst_chain_len(&p->sendq) == 0 && bst_chain_move(&p->sendq, &p->pend) != 0)
		return;
	if (bst_chain_len(&p->sendq) == 0)
		return;
	p->sending = true;
	if (bst_upconn_send(p->uc, &p->sendq, on_sent, p) != 0) {
		p->sending = false;
		upstream_error(p, -EIO);
		return;
	}
	bst_loop_timer_arm(p->loop, &p->wtm, p->up->send_timeout_ms, on_write_timeout, p);
}

static void begin_exchange(pctx *p)
{
	bst_stream *s = p->s;
	bst_h1_body_cfg bc = { .chunk_ext_limit = s->cfg->http.chunk_ext_limit,
			       .max_trailer = s->cfg->http.client_max_trailer_size };
	bst_h1_client_init(&p->rc, s->arena, p->pc->max_header, s->req.head.method == BST_M_HEAD,
			   &bc);
	p->rc_init = true;
	if (bst_upconn_recv_start(p->uc, on_up_recv, p) != 0) {
		upstream_error(p, -EIO);
		return;
	}
	p->recv_on = true;
	if (bst_chain_add_mem(&p->sendq, p->head, 0, p->head->len) != 0) {
		fail(p, 500);
		return;
	}
	bst_loop_timer_arm(p->loop, &p->rtm, p->up->read_timeout_ms, on_read_timeout, p);
	if (p->rqs != NULL) { /* the body is all in the spool: send it from the start */
		p->rq_epoch++;
		p->rq_pos = 0;
		kick_send(p);
		if (p->uc != NULL)
			rq_feed(p);
		return;
	}
	kick_send(p);
	if (p->s != NULL && p->req_body && !p->body_started) {
		p->body_started = true;
		bst_stream_read_body(s, p->pc->buffer_size);
	}
}

static void on_conn(void *ud, bst_upconn *c, int err)
{
	pctx *p = ud;
	enter(p);
	if (p->s == NULL) {
		if (c != NULL)
			bst_pool_close(c);
		goto out;
	}
	if (err != 0) {
		bst_log(BST_LOG_WARN, "proxy: connecting to %s failed: %s", p->sh->addr,
			err == -ETIMEDOUT ? "timed out" : strerror(-err));
		passive_fail(p);
		if (retry_other(p, err == -ETIMEDOUT ? BST_RETRY_ON_TIMEOUT : BST_RETRY_ON_ERROR, true))
			goto out;
		note_time(p);
		fail(p, err == -ETIMEDOUT ? 504 : 502);
		goto out;
	}
	p->uc = c;
	p->reused = false;
	begin_exchange(p);
out:
	leave(p);
}

/* ---- HTTP/2 upstreams (client_h2.h) ---- */

/* Copies fields into the stream arena: the upstream stream's own memory goes with it. */
static int copy_fields(bst_stream *s, const bst_headers *in, bst_headers *out)
{
	bst_headers_init(out, s->arena);
	for (uint32_t i = 0; i < in->n; i++) {
		const bst_header *f = &in->v[i];
		char *b = bst_arena_alloc(s->arena, (size_t)f->name.len + f->value.len + 1);
		if (b == NULL)
			return -1;
		memcpy(b, f->name.p, f->name.len);
		if (f->value.len > 0)
			memcpy(b + f->name.len, f->value.p, f->value.len);
		if (bst_headers_add(out, (bst_str){ b, f->name.len },
				    (bst_str){ b + f->name.len, f->value.len }) != 0)
			return -1;
	}
	return 0;
}

static void h2_on_head(void *ud, int status, const bst_headers *uh, bool end)
{
	pctx *p = ud;
	enter(p);
	if (p->s == NULL)
		goto out;
	bst_loop_timer_arm(p->loop, &p->rtm, p->up->read_timeout_ms, on_read_timeout, p);
	bst_headers cp;
	if (copy_fields(p->s, uh, &cp) != 0) {
		fail(p, 502);
		goto out;
	}
	int64_t clen = -1;
	const bst_header *cl = bst_headers_get(&cp, BST_H_CONTENT_LENGTH);
	uint64_t v;
	if (cl != NULL && bst_str_to_u64(cl->value, &v))
		clen = (int64_t)v;
	(void)send_head_of(p, status, &cp, end ? -1 : clen, end, true);
out:
	leave(p);
}

static void h2_on_data(void *ud, bst_chain *data, bool end)
{
	pctx *p = ud;
	enter(p);
	if (p->s == NULL)
		goto out;
	uint64_t n = bst_chain_len(data);
	if (n > 0 && bst_chain_move(&p->cpend, data) != 0) {
		fail(p, 502);
		goto out;
	}
	p->h2_unacked += (size_t)n;
	if (end) {
		finish_upstream(p, true);
		p->cend = true;
	} else {
		bst_loop_timer_arm(p->loop, &p->rtm, p->up->read_timeout_ms, on_read_timeout, p);
	}
	pump(p);
	if (p->s != NULL && p->csending)
		bst_timer_cancel(&p->rtm); /* the client is the slow one: resume_upstream re-arms */
out:
	leave(p);
}

static void h2_on_trailers(void *ud, const bst_headers *t)
{
	pctx *p = ud;
	enter(p);
	if (p->s == NULL)
		goto out;
	bst_headers cp;
	bst_headers_init(&p->tr, p->s->arena);
	if (copy_fields(p->s, t, &cp) != 0 || bst_proxy_resp_headers(p->s, &cp, &p->tr) != 0) {
		fail(p, 502);
		goto out;
	}
	p->has_tr = true;
	finish_upstream(p, true);
	p->cend = true;
	pump(p);
out:
	leave(p);
}

static void start_h2(pctx *p);

static void h2_on_error(void *ud, int err, int kind)
{
	pctx *p = ud;
	enter(p);
	if (p->s == NULL)
		goto out;
	bst_h2us_release(p->hs);
	p->hs = NULL;
	if (kind == BST_H2US_REFUSED && !p->head_sent && !p->body_sent && p->h2_refused < 3) {
		/* the peer never processed it (GOAWAY or REFUSED_STREAM): safe on another stream */
		p->h2_refused++;
		bst_log(BST_LOG_INFO, "proxy: HTTP/2 upstream %s refused a stream: reopening it",
			p->sh->addr);
		p->body_started = false;
		start_h2(p);
		goto out;
	}
	if (kind == BST_H2US_CONNECT) {
		bst_log(BST_LOG_WARN, "proxy: connecting to %s failed: %s", p->sh->addr,
			err == -ETIMEDOUT ? "timed out" : strerror(-err));
		passive_fail(p);
		if (retry_other(p, err == -ETIMEDOUT ? BST_RETRY_ON_TIMEOUT : BST_RETRY_ON_ERROR, true))
			goto out;
		fail(p, err == -ETIMEDOUT ? 504 : 502);
		goto out;
	}
	upstream_error(p, err);
out:
	leave(p);
}

static void h2_on_sent(void *ud)
{
	pctx *p = ud;
	enter(p);
	if (p->s != NULL && p->req_body && !p->req_done && p->body_started)
		bst_stream_read_body(p->s, p->pc->buffer_size); /* the next round of credit */
	leave(p);
}

static const bst_h2us_ops h2_ops = {
	.on_head = h2_on_head,
	.on_data = h2_on_data,
	.on_trailers = h2_on_trailers,
	.on_error = h2_on_error,
	.on_sent = h2_on_sent,
};

static void start_h2(pctx *p)
{
	p->attempts++;
	p->hs = bst_h2us_open(p->loop, p->up, p->peer, &p->addr, &p->h2req, p->req_body, &h2_ops, p);
	if (p->hs == NULL) {
		fail(p, 500);
		return;
	}
	bst_loop_timer_arm(p->loop, &p->rtm, p->up->read_timeout_ms, on_read_timeout, p);
	if (p->req_body && !p->body_started) {
		p->body_started = true;
		bst_stream_read_body(p->s, p->pc->buffer_size);
	}
}

/* The HTTP/2 request: pseudo-fields from the parsed request, then the regular fields. */
static int build_h2_request(pctx *p, const bst_headers *hs, bst_str host, bst_str target)
{
	bst_stream *s = p->s;
	const bst_req *rq = &s->req;
	bst_headers *o = &p->h2req;
	bst_headers_init(o, s->arena);
	if (bst_headers_add(o, BST_S(":method"), rq->head.method_str) != 0 ||
	    bst_headers_add(o, BST_S(":scheme"), p->up->tls ? BST_S("https") : BST_S("http")) != 0 ||
	    bst_headers_add(o, BST_S(":authority"), host) != 0 ||
	    bst_headers_add(o, BST_S(":path"), target) != 0)
		return -1;
	for (uint32_t i = 0; i < hs->n; i++)
		if (bst_headers_add(o, hs->v[i].name, hs->v[i].value) != 0)
			return -1;
	if (rq->framing.kind == BST_FRAMING_LENGTH) {
		char *v = bst_arena_alloc(s->arena, 24);
		if (v == NULL)
			return -1;
		int n = snprintf(v, 24, "%" PRIu64, rq->framing.length);
		if (bst_headers_add(o, BST_S("content-length"), (bst_str){ v, (uint32_t)n }) != 0)
			return -1;
	}
	/* gRPC needs TE: trailers end to end (hop-by-hop fields are otherwise never forwarded) */
	if ((p->grpc || bst_headers_list_has(&rq->head.headers, BST_H_TE, BST_S("trailers"))) &&
	    bst_headers_add(o, BST_S("te"), BST_S("trailers")) != 0)
		return -1;
	return 0;
}

static void start_connect(pctx *p, bool fresh)
{
	if (p->up->h2) {
		start_h2(p);
		return;
	}
	p->attempts++;
	bst_upconn *c = NULL;
	int rc;
	if (p->up->send_pp != 0) { /* the header names this client: a connection of its own */
		const bst_stream *s = p->s;
		const bst_sockaddr *src = s->has_peer ? &s->peer : NULL;
		const bst_sockaddr *dst = s->transport != NULL && s->transport->has_local ? &s->transport->local : NULL;
		uint8_t hb[BST_PP_V1_MAX + 1];
		size_t hl = p->up->send_pp == 2 ? bst_pp_write_v2(src, dst, hb, sizeof hb)
						: bst_pp_write_v1(src, dst, (char *)hb, sizeof hb);
		rc = hl == 0 ? -EINVAL : bst_pool_get_pp(p->loop, p->up, p->peer, &p->addr, hb, hl, on_conn, p);
	} else {
		rc = bst_pool_get(p->loop, p->up, p->peer, &p->addr, fresh, on_conn, p, &c);
	}
	if (rc < 0) {
		bst_log(BST_LOG_WARN, "proxy: no connection to %s: %s", p->sh->addr, strerror(-rc));
		fail(p, 502);
		return;
	}
	if (rc == 1) {
		p->uc = c;
		p->reused = true;
		begin_exchange(p);
	}
}

/* The request target sent upstream: the client's own bytes for the path and query (so encoded
 * bytes reach the upstream as sent), the rewritten path when a rewrite changed it, minus the
 * location's prefix for `proxy_uri strip_prefix`, after the URL's own path. */
static bst_str build_target(bst_stream *s)
{
	const bst_cfg_proxy *pc = &s->cfg->proxy;
	const bst_req_head *h = &s->req.head;
	if (h->form == BST_TARGET_ASTERISK)
		return BST_S("*");
	bst_str path = h->path;
	char *enc = NULL;
	if (s->uri_changed || path.len == 0) {
		/* the decoded, rewritten path: encode what may not appear raw in a path */
		static const char hex[] = "0123456789ABCDEF";
		enc = bst_arena_alloc(s->arena, (size_t)s->uri.len * 3 + 1);
		if (enc == NULL)
			return (bst_str){ NULL, 0 };
		size_t k = 0;
		for (size_t i = 0; i < s->uri.len; i++) {
			unsigned char c = (unsigned char)s->uri.p[i];
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			    strchr("-._~!$&'()*+,;=:@/", c) != NULL) {
				enc[k++] = (char)c;
			} else {
				enc[k++] = '%';
				enc[k++] = hex[c >> 4];
				enc[k++] = hex[c & 15];
			}
		}
		path = (bst_str){ enc, (uint32_t)k };
	}
	if (pc->uri == BST_PROXY_URI_STRIP_PREFIX && s->loc != NULL && s->loc->mod != BST_LOC_REGEX &&
	    s->loc->mod != BST_LOC_REGEX_I) {
		size_t pl = strlen(s->loc->pattern);
		if (pl > 1 && s->loc->pattern[pl - 1] == '/')
			pl--; /* /api/ strips /api and keeps the slash */
		if (path.len >= pl && memcmp(path.p, s->loc->pattern, pl) == 0) {
			path.p += pl;
			path.len -= (uint32_t)pl;
		}
	}
	size_t ul = strlen(pc->url_path);
	bool slash = path.len == 0 || path.p[0] != '/';
	size_t n = ul + (slash ? 1 : 0) + path.len + (h->has_query ? 1 + h->query.len : 0);
	char *b = bst_arena_alloc(s->arena, n + 1);
	if (b == NULL)
		return (bst_str){ NULL, 0 };
	size_t k = 0;
	memcpy(b, pc->url_path, ul);
	k += ul;
	if (slash)
		b[k++] = '/';
	memcpy(b + k, path.p, path.len);
	k += path.len;
	if (h->has_query) {
		b[k++] = '?';
		memcpy(b + k, h->query.p, h->query.len);
		k += h->query.len;
	}
	return (bst_str){ b, (uint32_t)k };
}

/* Picks the server and starts the exchange (after the whole body, with request_buffering). */
static void dispatch(pctx *p)
{
	bst_stream *s = p->s;
	bst_retry_note_request(p->up);
	bst_pick_ctx pk = { .s = s };
	p->peer = bst_balance_pick(p->up, &pk, &p->addr);
	if (p->peer == NULL) {
		if (bst_upstream_any_addr(p->up)) {
			/* every server is down: answer at once, nothing waits or spins */
			bst_log(BST_LOG_WARN, "proxy: upstream %s has no healthy server: 503",
				p->up->name);
			unavailable(p, 1);
		} else {
			bst_log(BST_LOG_WARN, "proxy: upstream %s has no server with an address: 502",
				p->up->name);
			fail(p, 502);
		}
		return;
	}
	set_addr_var(p);
	p->brk = bst_breaker_of(p->up);
	if (p->brk != NULL) {
		uint64_t now = bst_loop_now_ms(p->loop);
		if (!bst_breaker_admit(p->brk, now, &p->brk_probe)) {
			bst_log(BST_LOG_WARN, "proxy: upstream %s: circuit breaker refused the request: "
					      "503", p->up->name);
			unavailable(p, bst_breaker_retry_after(p->brk, now));
			return;
		}
		p->brk_counted = true;
		p->brk_pending = true;
	}
	start_connect(p, false);
}

static void on_request(bst_stream *s)
{
	shell *sh = bst_arena_alloc(s->arena, sizeof *sh);
	pctx *p = sh == NULL ? NULL : calloc(1, sizeof *p);
	if (p == NULL) {
		(void)bst_send_error(s, 500);
		return;
	}
	memset(sh, 0, sizeof *sh);
	sh->p = p;
	s->hctx = sh;
	p->s = s;
	p->sh = sh;
	p->pc = &s->cfg->proxy;
	p->up = p->pc->up;
	p->loop = bst_worker_loop(s->worker);
	p->t0 = bst_loop_now_ms(p->loop);
	bst_timer_init(&p->rtm);
	bst_timer_init(&p->wtm);
	bst_timer_init(&p->tidle);
	bst_timer_init(&p->tmax);
	bst_chain_init(&p->sendq, s->chain_slab);
	bst_chain_init(&p->pend, s->chain_slab);
	bst_chain_init(&p->cpend, s->chain_slab);
	enter(p);
	bst_headers hs;
	bst_headers_init(&hs, s->arena);
	bst_str host;
	if (bst_proxy_req_headers(s, &hs, &host) != 0) {
		fail(p, 500);
		goto out;
	}
	const bst_header *ct = bst_headers_get(&s->req.head.headers, BST_H_CONTENT_TYPE);
	p->grpc = ct != NULL && ct->value.len >= 16 &&
		  bst_str_ieq((bst_str){ ct->value.p, 16 }, BST_S("application/grpc")) &&
		  (ct->value.len == 16 || ct->value.p[16] == '+' || ct->value.p[16] == ';');
	bool ext = s->req.head.method == BST_M_CONNECT && s->req.head.protocol.len > 0;
	if (ext && (!p->pc->websocket || p->up->h2)) {
		bst_log(BST_LOG_WARN, "proxy: extended CONNECT for %s refused: %s: 501",
			p->up->name, p->up->h2 ? "the upstream is HTTP/2" : "websocket is off");
		fail(p, 501);
		goto out;
	}
	if (ext) {
		/* RFC 8441 and RFC 9220: the upstream gets the HTTP/1.1 Upgrade it understands, with a
		 * key of ours (the client sent none) */
		if (!bst_tunnel_acquire(p->pc->max_tunnels)) {
			bst_log(BST_LOG_WARN, "proxy: max_tunnels (%u) reached: 503", p->pc->max_tunnels);
			unavailable(p, 1);
			goto out;
		}
		p->tun_slot = true;
		p->ws = true;
		p->ws_ext = true;
		if (bst_tunnel_make_key(p->ws_key) != 0 ||
		    bst_headers_add(&hs, BST_S("Connection"), BST_S("upgrade")) != 0 ||
		    bst_headers_add(&hs, BST_S("Upgrade"), BST_S("websocket")) != 0 ||
		    bst_headers_add(&hs, BST_S("Sec-WebSocket-Key"),
				    (bst_str){ p->ws_key, (uint32_t)strlen(p->ws_key) }) != 0 ||
		    (bst_headers_get_name(&hs, BST_S("sec-websocket-version")) == NULL &&
		     bst_headers_add(&hs, BST_S("Sec-WebSocket-Version"), BST_S("13")) != 0)) {
			fail(p, 500);
			goto out;
		}
	} else if (p->pc->websocket && !p->up->h2 && bst_tunnel_ws_request(s)) {
		if (!bst_tunnel_acquire(p->pc->max_tunnels)) {
			bst_log(BST_LOG_WARN, "proxy: max_tunnels (%u) reached: 503", p->pc->max_tunnels);
			unavailable(p, 1);
			goto out;
		}
		p->tun_slot = true;
		p->ws = true;
		if (bst_headers_add(&hs, BST_S("Connection"), BST_S("upgrade")) != 0 ||
		    bst_headers_add(&hs, BST_S("Upgrade"), BST_S("websocket")) != 0) {
			fail(p, 500);
			goto out;
		}
	}
	bst_proxy_real_ip(s); /* after the forwarding fields, which name the connection's peer */
	const bst_req *rq = &s->req;
	p->req_body = rq->framing.kind == BST_FRAMING_CHUNKED ||
		      (rq->framing.kind == BST_FRAMING_LENGTH && rq->framing.length > 0);
	p->req_chunked = rq->framing.kind == BST_FRAMING_CHUNKED;
	if (ext) { /* no body until the tunnel opens: its bytes then flow as the tunnel's */
		p->req_body = false;
		p->req_chunked = false;
	}
	bst_h1_req_out ro = { .method = ext ? BST_S("GET") : rq->head.method_str,
			      .target = build_target(s), .host = host,
			      .headers = &hs, .chunked = p->req_chunked,
			      .has_length = rq->framing.kind == BST_FRAMING_LENGTH ||
					    (!p->req_body && (rq->head.method == BST_M_POST ||
							      rq->head.method == BST_M_PUT ||
							      rq->head.method == BST_M_PATCH)),
			      .length = rq->framing.kind == BST_FRAMING_LENGTH ? rq->framing.length : 0 };
	if (ro.target.p == NULL || (p->head = bst_h1_req_head(&ro)) == NULL) {
		bst_log(BST_LOG_WARN, "proxy: the request can not be written as HTTP/1.1 (a field "
				      "holds a byte that would split it): 400");
		fail(p, 400);
		goto out;
	}
	if (p->up->h2 && build_h2_request(p, &hs, host, ro.target) != 0) {
		fail(p, 500);
		goto out;
	}
	p->rs_on = p->pc->resp_buffering && !p->ws && !p->up->h2;
	if (p->pc->req_buffering && p->req_body && !p->up->h2) {
		/* request_buffering: the whole body first; the upstream is chosen once it is here */
		p->rqs = bst_spool_open(s->worker, p->pc->spool_mem);
		if (p->rqs == NULL) {
			fail(p, 500);
			goto out;
		}
		p->rq_hs = hs;
		p->ro = ro;
		p->ro.headers = &p->rq_hs;
		p->body_started = true;
		bst_stream_read_body(s, p->pc->buffer_size);
		goto out;
	}
	dispatch(p);
out:
	leave(p);
}

static void on_body(bst_stream *s, bst_chain *in, bool end)
{
	shell *sh = s->hctx;
	pctx *p = sh != NULL ? sh->p : NULL;
	if (p == NULL || p->dead) {
		bst_chain_clear(in);
		return;
	}
	enter(p);
	uint64_t n = bst_chain_len(in);
	tunnel_touch(p);
	if (p->up->h2) {
		if (n > 0)
			p->body_sent = true;
		if (end)
			p->req_done = true;
		if (p->hs == NULL || bst_h2us_send(p->hs, in, end) != 0)
			bst_chain_clear(in); /* the stream ended: its outcome is decided elsewhere */
		goto out;
	}
	if (p->rqs != NULL && !p->req_done) { /* request_buffering: into the spool */
		int wr = n > 0 ? bst_spool_write(p->rqs, in) : 0;
		if (wr != 0) {
			bool full = wr == -ENOSPC || wr == -EDQUOT;
			bst_log(BST_LOG_ERROR, "proxy: spooling the request body failed: %s%s", strerror(-wr),
				full ? ": 507" : ": 500");
			fail(p, full ? 507 : 500);
			goto out;
		}
		if (!end) {
			bst_stream_read_body(s, p->pc->buffer_size); /* the next round of credit */
			goto out;
		}
		/* the whole body is here: its length is known, the head says so */
		p->req_done = true;
		p->req_chunked = false;
		p->ro.chunked = false;
		p->ro.has_length = true;
		p->ro.length = bst_spool_size(p->rqs);
		bst_buf *h = bst_h1_req_head(&p->ro);
		if (h == NULL) {
			fail(p, 500);
			goto out;
		}
		bst_buf_unref(p->head);
		p->head = h;
		p->body_sent = true;
		dispatch(p);
		goto out;
	}
	if (n > 0) {
		p->body_sent = true;
		if (p->req_chunked) {
			char hdr[24];
			int hl = snprintf(hdr, sizeof hdr, "%" PRIx64 "\r\n", n);
			bst_buf *hb = bst_buf_new((size_t)hl + 2);
			if (hb == NULL) {
				fail(p, 500);
				goto out;
			}
			memcpy(hb->data, hdr, (size_t)hl);
			memcpy(hb->data + hl, "\r\n", 2);
			hb->len = (size_t)hl + 2;
			int rc = bst_chain_add_mem(&p->pend, hb, 0, (size_t)hl);
			rc = rc || bst_chain_move(&p->pend, in);
			rc = rc || bst_chain_add_mem(&p->pend, hb, (size_t)hl, 2);
			bst_buf_unref(hb);
			if (rc != 0) {
				fail(p, 500);
				goto out;
			}
		} else if (bst_chain_move(&p->pend, in) != 0) {
			fail(p, 500);
			goto out;
		}
	}
	if (end) {
		p->req_done = true;
		if (p->req_chunked) {
			bst_buf *t = bst_buf_new(5);
			if (t == NULL) {
				fail(p, 500);
				goto out;
			}
			memcpy(t->data, "0\r\n\r\n", 5);
			t->len = 5;
			int rc = bst_chain_add_mem(&p->pend, t, 0, 5);
			bst_buf_unref(t);
			if (rc != 0) {
				fail(p, 500);
				goto out;
			}
		}
	}
	kick_send(p);
	if (p->s != NULL)
		tunnel_half_close(p);
out:
	bst_chain_clear(in);
	leave(p);
}

static void on_reset(bst_stream *s, bst_stream_err why)
{
	(void)why;
	shell *sh = s->hctx;
	pctx *p = sh != NULL ? sh->p : NULL;
	if (p == NULL)
		return;
	enter(p);
	if (p->uc != NULL) {
		bst_pool_close(p->uc); /* mid-exchange: never back to the pool */
		p->uc = NULL;
	}
	bst_h2us_release(p->hs); /* RST_STREAM CANCEL: a gRPC deadline or cancel reaches it */
	p->hs = NULL;
	detach(p);
	leave(p);
}

const bst_handler_ops bst_proxy_handler = {
	.on_request = on_request,
	.on_body = on_body,
	.on_reset = on_reset,
};

/* ---- variables ---- */

static const shell *shell_of(const bst_var_ctx *c)
{
	return c->s->handler == &bst_proxy_handler ? c->s->hctx : NULL;
}

static bst_str var_upstream_addr(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	const shell *sh = shell_of(c);
	if (sh == NULL || sh->addr[0] == 0)
		return (bst_str){ "", 0 };
	return (bst_str){ sh->addr, (uint32_t)strlen(sh->addr) };
}

static bst_str time_str(bst_stream *s, uint64_t ms)
{
	char *buf = bst_arena_alloc(s->arena, 32);
	if (buf == NULL)
		return (bst_str){ "", 0 };
	int n = snprintf(buf, 32, "%" PRIu64 ".%03" PRIu64, ms / 1000, ms % 1000);
	return (bst_str){ buf, (uint32_t)(n > 0 ? n : 0) };
}

static bst_str var_upstream_status(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	const shell *sh = shell_of(c);
	if (sh == NULL || sh->status == 0)
		return (bst_str){ "", 0 };
	char *buf = bst_arena_alloc(c->s->arena, 4);
	if (buf == NULL)
		return (bst_str){ "", 0 };
	snprintf(buf, 4, "%03d", sh->status % 1000);
	return (bst_str){ buf, 3 };
}

static bst_str var_upstream_time(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	const shell *sh = shell_of(c);
	if (sh == NULL || !sh->has_time)
		return (bst_str){ "", 0 };
	return time_str(c->s, sh->ms);
}

static const bst_var_def proxy_vars[] = {
	{ "upstream_addr", var_upstream_addr, false },
	{ "upstream_status", var_upstream_status, false },
	{ "upstream_response_time", var_upstream_time, false },
};
BST_VARS(proxy_vars);

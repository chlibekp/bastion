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

#include "core/log.h"
#include "proc/worker.h"
#include "proxy/balance.h"
#include "proxy/breaker.h"
#include "proxy/client_h1.h"
#include "proxy/pool.h"
#include "proxy/retry.h"
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
	bst_timer tidle, tmax;
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
	bst_chain_clear(&p->sendq);
	bst_chain_clear(&p->pend);
	bst_chain_clear(&p->cpend);
	bst_buf_unref(p->head);
	if (p->rc_init)
		bst_h1_client_free(&p->rc);
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
	bool sent = p->head_sent;
	detach(p);
	if (!sent)
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
	detach(p);
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
	if (!connect_level && (!idempotent(s->req.head.method) || p->req_body))
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
static void pump(pctx *p)
{
	if (p->csending || p->s == NULL)
		return;
	if (bst_chain_len(&p->cpend) == 0 && !p->cend) {
		resume_upstream(p);
		return;
	}
	bst_stream *s = p->s;
	if (p->cend) {
		note_time(p);
		detach(p);
		(void)bst_stream_send_body(s, &p->cpend, true, NULL, NULL);
		return;
	}
	p->csending = true;
	if (bst_stream_send_body(s, &p->cpend, false, client_done, p) != 0) {
		p->csending = false; /* the stream is gone: on_reset follows or already ran */
	}
}

/* The upstream's part is over: keep the connection when it may carry another exchange. */
static void finish_upstream(pctx *p, bool reusable)
{
	bst_timer_cancel(&p->rtm);
	bst_timer_cancel(&p->wtm);
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

static int send_head(pctx *p)
{
	bst_stream *s = p->s;
	const bst_h1_client *rc = &p->rc;
	p->sh->status = rc->head.status;
	if (rc->head.status >= 500) {
		passive_fail(p);
		int st = rc->head.status;
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
	if (p->pc->intercept_errors && rc->head.status >= 400) {
		finish_upstream(p, false);
		note_time(p);
		detach(p);
		(void)bst_send_error(s, rc->head.status); /* error_page applies */
		return -1;
	}
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = rc->head.status;
	h.content_length = -1;
	if (rc->fr.kind == BST_RESP_BODY_LENGTH)
		h.content_length = (int64_t)rc->fr.length;
	bst_headers_init(&h.headers, s->arena);
	if (bst_proxy_resp_headers(s, &rc->head.headers, &h.headers) != 0) {
		fail(p, 502);
		return -1;
	}
	bool end = rc->fr.kind == BST_RESP_BODY_NONE ||
		   (rc->fr.kind == BST_RESP_BODY_LENGTH && rc->fr.length == 0);
	if (s->req.head.method == BST_M_HEAD) {
		const bst_header *cl = bst_headers_get(&rc->head.headers, BST_H_CONTENT_LENGTH);
		uint64_t v;
		if (cl != NULL && bst_str_to_u64(cl->value, &v))
			h.content_length = (int64_t)v; /* what a GET would have had */
	}
	p->head_sent = true;
	if (end) {
		finish_upstream(p, bst_h1_client_reusable(rc));
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
	if (bst_proxy_resp_headers(s, uh, &h.headers) != 0 ||
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
			if (p->s != NULL && p->csending && p->recv_on && p->uc != NULL) {
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

static void start_connect(pctx *p, bool fresh)
{
	p->attempts++;
	bst_upconn *c = NULL;
	int rc = bst_pool_get(p->loop, p->up, p->peer, &p->addr, fresh, on_conn, p, &c);
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
	if (p->pc->websocket && bst_tunnel_ws_request(s)) {
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
	bst_h1_req_out ro = { .method = rq->head.method_str, .target = build_target(s), .host = host,
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
		goto out;
	}
	set_addr_var(p);
	p->brk = bst_breaker_of(p->up);
	if (p->brk != NULL) {
		uint64_t now = bst_loop_now_ms(p->loop);
		if (!bst_breaker_admit(p->brk, now, &p->brk_probe)) {
			bst_log(BST_LOG_WARN, "proxy: upstream %s: circuit breaker refused the request: "
					      "503", p->up->name);
			unavailable(p, bst_breaker_retry_after(p->brk, now));
			goto out;
		}
		p->brk_counted = true;
		p->brk_pending = true;
	}
	start_connect(p, false);
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

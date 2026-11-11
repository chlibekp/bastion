/* HTTP/1.1 connection state machine. See conn.h for the model.
 *
 * Re-entrancy. Handlers call back into the stream from inside our callbacks, and a callback may
 * close the connection. Every entry point therefore brackets itself with h1c_enter/h1c_leave: h1c_close
 * releases everything at once but the h1c itself is freed when the last bracket is left. */
#include "http/h1/conn_priv.h"

#include "core/log.h"
#include "tls/conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ARENA_CHUNK 4096u /* a stream's arena grows by this much; also its share of the memory budget */


static h1c *g_conns;
static bst_slab *g_slab;

static void consume(h1c *c, bst_buf *b, size_t off);
static void on_recv(void *ud, bst_buf *data, int err);


/* ---- streams ---- */

static void stream_free(h1s *s)
{
	bst_chain_clear(&s->in);
	bst_chain_clear(&s->pre);
	bst_chain_clear(&s->out);
	if (s->charged > 0)
		bst_worker_mem_release(s->c->w, s->charged);
	bst_arena_free(s->s.arena);
	free(s);
}

static h1s *stream_new(h1c *c)
{
	h1s *s = calloc(1, sizeof *s);
	if (s == NULL)
		return NULL;
	s->s.arena = bst_arena_new(ARENA_CHUNK);
	if (s->s.arena == NULL) {
		free(s);
		return NULL;
	}
	s->c = c;
	s->cl_left = -1;
	bst_chain_init(&s->in, g_slab);
	bst_chain_init(&s->pre, g_slab);
	bst_chain_init(&s->out, g_slab);
	bst_headers_init(&s->trailers, s->s.arena);
	s->s.ops = &bst_h1_ops;
	s->s.proto = s;
	s->s.worker = c->w;
	s->s.transport = c->t;
	s->s.peer = c->peer;
	s->s.has_peer = c->has_peer;
	s->s.chain_slab = g_slab;
	s->s.server = bst_vhost_default(c->set);
	s->s.cfg = &bst_vhost_default(c->set)->common;
	bst_headers_init(&s->s.req.head.headers, s->s.arena);
	return s;
}

static void enqueue(h1c *c, h1s *s)
{
	if (c->tail != NULL)
		c->tail->next = s;
	else
		c->head = s;
	c->tail = s;
	c->nq++;
}

static void reset_handler(h1s *s, bst_stream_err why)
{
	if (s->detached)
		return;
	s->detached = true;
	s->cb = NULL;
	if (s->s.handler != NULL && s->s.handler->on_reset != NULL)
		s->s.handler->on_reset(&s->s, why);
}

/* ---- timers ---- */

static void send_timeout_cb(void *ud);

static void arm_send(h1c *c, uint64_t bytes)
{
	const bst_cfg_http *hc = c->hc;
	uint64_t ms = hc->send_timeout_ms;
	if (hc->send_min_rate > 0) { /* the whole write must average send_min_rate */
		uint64_t need = bytes * 1000 / hc->send_min_rate;
		if (need > ms)
			ms = need;
	}
	bst_loop_timer_arm(c->loop, &c->t_send, ms, send_timeout_cb, c);
}

static void send_timeout_cb(void *ud)
{
	h1c *c = ud;
	h1c_enter(c);
	bst_log(BST_LOG_DEBUG, "h1: send below send_min_rate, closing");
	h1c_close(c);
	h1c_leave(c);
}

/* ---- connection end ---- */

void h1c_close(h1c *c)
{
	if (c->closed)
		return;
	c->closed = true;
	if (c->prev != NULL)
		c->prev->next = c->next;
	else
		g_conns = c->next;
	if (c->next != NULL)
		c->next->prev = c->prev;
	bst_timer_cancel(&c->t_head);
	bst_timer_cancel(&c->t_body);
	bst_timer_cancel(&c->t_send);
	bst_timer_cancel(&c->t_flush);
	c->t->ops->close(c->t);
	if (c->held != NULL)
		bst_buf_unref(c->held);
	c->held = NULL;
	h1s *s = c->head;
	c->head = c->tail = c->body_s = NULL;
	while (s != NULL) {
		h1s *nx = s->next;
		reset_handler(s, BST_STREAM_ERR_CANCEL);
		stream_free(s);
		s = nx;
	}
	if (c->cur != NULL)
		stream_free(c->cur);
	c->cur = NULL;
	bst_chain_clear(&c->wchain);
	free(c->hbuf);
	c->hbuf = NULL;
	bst_worker_conn_closed(c->w);
	if (c->depth == 0)
		free(c);
}

static void on_linger_timeout(void *ud)
{
	h1c *c = ud;
	h1c_enter(c);
	h1c_close(c);
	h1c_leave(c);
}

/* After the last response: close now, or send FIN and keep reading for a while so unread
 * request bytes do not turn into an RST that eats the response (RFC 9112 section 9.6). */
static void finish_conn(h1c *c)
{
	if (c->closed)
		return;
	if (c->hc->lingering_close && (c->unread || c->held != NULL)) {
		c->lingering = true;
		c->mode = M_DISCARD;
		bst_timer_cancel(&c->t_body);
		bst_timer_cancel(&c->t_send);
		bst_timer_cancel(&c->t_flush);
		c->t->ops->shutdown(c->t, NULL, NULL);
		bst_loop_timer_arm(c->loop, &c->t_head, c->hc->lingering_timeout_ms, on_linger_timeout, c);
		h1c_update_recv(c);
	} else {
		h1c_close(c);
	}
}

/* ---- writing ---- */

static void stream_done(h1c *c, h1s *s);

static void on_written(void *ud, size_t bytes, int err)
{
	h1c *c = ud;
	h1c_enter(c);
	c->writing = false;
	bst_timer_cancel(&c->t_send);
	if (err != 0) {
		h1c_close(c);
		h1c_leave(c);
		return;
	}
	bst_chain_clear(&c->wchain);
	bst_done_cb cb = c->wr_cb;
	void *cb_ud = c->wr_ud;
	c->wr_cb = NULL;
	if (cb != NULL)
		cb(cb_ud, bytes, 0);
	h1c_pump(c);
	h1c_leave(c);
}

void h1c_pump(h1c *c)
{
	for (;;) {
		h1s *s = c->head;
		if (s == NULL || c->writing || c->closed)
			return;
		bool pre = s->pre.len > 0 && (s->head_ready || s->pre_flush);
		bool out = s->out.len > 0;
		if (!pre && !out && s->cb == NULL) {
			if (s->resp_done && s->pre.len == 0) {
				stream_done(c, s);
				continue;
			}
			return;
		}
		if (pre)
			(void)bst_chain_move(&c->wchain, &s->pre);
		if (out)
			(void)bst_chain_move(&c->wchain, &s->out);
		c->wr_s = s;
		c->wr_cb = s->cb;
		c->wr_ud = s->cb_ud;
		s->cb = NULL;
		c->writing = true;
		arm_send(c, bst_chain_len(&c->wchain));
		if (c->t->ops->send(c->t, &c->wchain, on_written, c) != 0) {
			c->writing = false;
			h1c_close(c);
		}
		return;
	}
}

static void on_flush(void *ud);

void h1c_arm_flush(h1c *c)
{
	if (c->flush_armed || c->closed)
		return;
	c->flush_armed = true;
	bst_loop_timer_arm(c->loop, &c->t_flush, 1, on_flush, c);
}

static void on_flush(void *ud)
{
	h1c *c = ud;
	h1c_enter(c);
	c->flush_armed = false;
	h1c_pump(c);
	h1c_leave(c);
}

static void on_head_timeout(void *ud);

static void arm_idle(h1c *c)
{
	if (c->closed || c->cur != NULL || c->nq != 0 || c->mode != M_HEAD || c->no_more)
		return;
	bst_loop_timer_arm(c->loop, &c->t_head, c->hc->keepalive_timeout_ms, on_head_timeout, c);
}

static void resume(h1c *c)
{
	if (c->closed)
		return;
	if (c->held != NULL && c->no_more) {
		bst_buf_unref(c->held);
		c->held = NULL;
	}
	if (c->held != NULL && c->mode == M_HEAD && c->nq < c->hc->http1_max_pipeline) {
		bst_buf *b = c->held;
		size_t off = c->held_off;
		c->held = NULL;
		consume(c, b, off);
		bst_buf_unref(b);
	}
	h1c_update_recv(c);
}

/* A response is fully written. */
static void stream_done(h1c *c, h1s *s)
{
	c->head = s->next;
	if (c->head == NULL)
		c->tail = NULL;
	c->nq--;
	if (c->body_s == s)
		c->body_s = NULL;
	bool close = s->close_after;
	stream_free(s);
	if (close) {
		finish_conn(c);
		return;
	}
	if (c->head == NULL)
		arm_idle(c);
	resume(c);
}

/* ---- request body ---- */

void h1c_deliver(h1s *s)
{
	h1c *c = s->c;
	while (!c->closed && s->reading && !s->detached && s->s.handler != NULL) {
		bool data = s->in.len > 0;
		if (!data && !(s->body_done && !s->end_sent))
			break;
		if (data && s->credit == 0)
			break;
		if (data)
			s->credit = s->credit > s->in.len ? s->credit - s->in.len : 0;
		bool end = s->body_done;
		if (end) {
			s->end_sent = true;
			if (s->trailers.n > 0 && s->s.handler->on_trailers != NULL)
				s->s.handler->on_trailers(&s->s, &s->trailers);
		}
		if (s->s.handler->on_body != NULL)
			s->s.handler->on_body(&s->s, &s->in, end);
		bst_chain_clear(&s->in);
		if (end)
			break;
	}
}

/* Stops reading the request body: the connection will close once the response is out. */
void h1c_force_discard(h1c *c, h1s *s)
{
	bst_timer_cancel(&c->t_body);
	c->body_s = NULL;
	c->mode = M_DISCARD;
	c->no_more = true;
	c->unread = true;
	s->close_after = true;
	bst_chain_clear(&s->in);
}

static void body_fail(h1c *c, h1s *s, int status)
{
	h1c_force_discard(c, s);
	reset_handler(s, status == 408 ? BST_STREAM_ERR_TIMEOUT : BST_STREAM_ERR_PROTOCOL);
	if (s->head_sent) { /* the response has begun: it cannot become an error page */
		h1c_close(c);
		return;
	}
	s->own = true;
	(void)bst_send_error(&s->s, status);
	s->own = false;
}

static void on_body_timer(void *ud)
{
	h1c *c = ud;
	h1c_enter(c);
	h1s *s = c->body_s;
	if (s != NULL && !c->closed) {
		const bst_cfg_http *h = &s->s.cfg->http;
		bool paused = s->in.len > 0 && s->credit == 0; /* our own pause is not the client's */
		uint64_t need = h->client_body_min_rate * h->client_body_timeout_ms / 1000;
		if (!paused && (c->win_bytes == 0 || c->win_bytes < need)) {
			body_fail(c, s, 408);
		} else {
			c->win_bytes = 0;
			bst_loop_timer_arm(c->loop, &c->t_body, h->client_body_timeout_ms, on_body_timer, c);
		}
	}
	h1c_leave(c);
}

static size_t body_step(h1c *c, bst_buf *b, size_t off)
{
	h1s *s = c->body_s;
	int st = 0;
	size_t o = off;
	bst_h1_body_kind k = bst_h1_body_feed(&s->body, b, &o, &s->in, &s->trailers, &st);
	c->win_bytes += o - off;
	if (k == BST_H1_BODY_ERROR) {
		body_fail(c, s, st);
		return b->len;
	}
	if (k == BST_H1_BODY_DONE) {
		s->body_done = true;
		c->body_s = NULL;
		c->mode = M_HEAD;
		bst_timer_cancel(&c->t_body);
		h1c_deliver(s);
		return o;
	}
	h1c_deliver(s);
	return b->len;
}

/* ---- request head ---- */

static bool hbuf_append(h1c *c, const char *p, size_t n)
{
	if (c->hlen + n > c->hcap) {
		size_t cap = c->hcap ? c->hcap : c->hc->client_header_buffer_size;
		while (cap < c->hlen + n)
			cap *= 2;
		char *nb = realloc(c->hbuf, cap);
		if (nb == NULL)
			return false;
		c->hbuf = nb;
		c->hcap = cap;
	}
	memcpy(c->hbuf + c->hlen, p, n);
	c->hlen += n;
	return true;
}

/* Answers a request that will not run. keep: the connection may carry the next request. */
static void reject(h1c *c, h1s *s, int status, bst_str hname, bst_str hval, bool keep)
{
	c->cur = NULL;
	c->hlen = 0;
	c->served++;
	bst_timer_cancel(&c->t_head);
	s->s.req.framing = (bst_framing){ BST_FRAMING_NONE, 0 };
	s->body_done = true;
	if (!keep) {
		s->close_after = true;
		c->no_more = true;
		c->unread = true;
		c->mode = M_DISCARD;
	}
	enqueue(c, s);
	s->own = true;
	if (hname.len > 0)
		(void)bst_send_error_hdr(&s->s, status, hname, hval);
	else
		(void)bst_send_error(&s->s, status);
	s->own = false;
}

static void head_done(h1c *c, h1s *s)
{
	bst_req *rq = &s->s.req;
	const bst_str none = { NULL, 0 };
	c->cur = NULL;
	c->hlen = 0;
	bst_timer_cancel(&c->t_head);
	int st = 0;
	rq->framing = bst_h1_message_framing(&rq->head, &st);
	if (st == 0)
		st = bst_validate_request_semantics(rq);
	if (st != 0) {
		/* The framing is sound, so a refusal of what was asked (405, 417) can leave the
		 * connection usable; a malformed head cannot. */
		bool keep = (st == 405 || st == 417) && rq->framing.kind == BST_FRAMING_NONE &&
			    rq->keepalive && !c->draining;
		reject(c, s, st, none, none, keep);
		return;
	}
	s->is_head = rq->head.method == BST_M_HEAD;
	bool matched = true;
	s->s.server = bst_vhost_lookup(c->set, rq->host, &matched);
	s->s.cfg = &s->s.server->common;
	if (!matched && bst_vhost_default(c->set)->unknown_host == BST_UNKNOWN_HOST_CLOSE) {
		stream_free(s); /* not queued yet: the connection is dropped without a response */
		h1c_close(c);
		return;
	}
	if (!matched && bst_vhost_default(c->set)->unknown_host == BST_UNKNOWN_HOST_421) {
		bool keep = rq->framing.kind == BST_FRAMING_NONE && rq->keepalive && !c->draining;
		reject(c, s, 421, none, none, keep);
		return;
	}
	const bst_cfg_server *sni = bst_tls_sni_server(c->t), *chosen = bst_tls_chosen_server(c->t);
	/* A server that asks for client certificates is never reachable through a handshake made for
	 * another server (or none): its certificate check was not made, whatever Host says. */
	bool mtls_cross = chosen != NULL && chosen != s->s.server &&
			  (s->s.server->tls.client_auth != BST_CLIENT_AUTH_OFF ||
			   chosen->tls.client_auth != BST_CLIENT_AUTH_OFF);
	if (mtls_cross || (sni != NULL && sni != s->s.server && sni->tls.host_sni == BST_HOST_SNI_421)) {
		/* The certificate was chosen for another server than the request addresses
		 * (RFC 9110 section 7.4): connection coalescing across hosts is refused. */
		bool keep = rq->framing.kind == BST_FRAMING_NONE && rq->keepalive && !c->draining;
		reject(c, s, 421, none, none, keep);
		return;
	}
	const bst_cfg_common *cfg = s->s.cfg;
	if (rq->framing.kind == BST_FRAMING_LENGTH && cfg->client_max_body_size != 0 &&
	    rq->framing.length > cfg->client_max_body_size) {
		reject(c, s, 413, none, none, false);
		return;
	}
	size_t charge = sizeof *s + ARENA_CHUNK;
	if (bst_overloaded(c->w) || !bst_worker_mem_charge(c->w, charge)) {
		const bst_cfg_limits *lim = bst_worker_limits(c->w);
		char ra[16];
		int n = snprintf(ra, sizeof ra, "%u", lim->overload_retry_after);
		char *v = bst_arena_alloc(s->s.arena, 16);
		if (v != NULL && n > 0)
			memcpy(v, ra, (size_t)n);
		bst_worker_refused(c->w);
		bool keep = rq->framing.kind == BST_FRAMING_NONE && rq->keepalive && !c->draining;
		reject(c, s, (int)lim->overload_status, BST_S("Retry-After"),
		       (bst_str){ v, v != NULL && n > 0 ? (uint32_t)n : 0 }, keep);
		return;
	}
	s->charged = charge;
	bool last = !rq->keepalive || c->hc->keepalive_timeout_ms == 0 ||
		    c->served + 1 >= c->hc->keepalive_requests || c->draining;
	c->served++;
	if (last) {
		s->close_after = true;
		c->no_more = true;
	}
	enqueue(c, s);
	if (rq->framing.kind != BST_FRAMING_NONE) {
		bst_h1_body_cfg bc = { .max_body = cfg->client_max_body_size,
				       .chunk_ext_limit = cfg->http.chunk_ext_limit,
				       .max_trailer = cfg->http.client_max_trailer_size };
		bst_h1_body_init(&s->body, rq->framing, &bc, s->s.arena);
		c->mode = M_BODY;
		c->body_s = s;
		c->win_bytes = 0;
		bst_loop_timer_arm(c->loop, &c->t_body, cfg->http.client_body_timeout_ms, on_body_timer, c);
	} else {
		s->body_done = true;
		c->mode = M_HEAD;
	}
	bst_stream_dispatch(&s->s);
}

static size_t head_step(h1c *c, bst_buf *b, size_t off)
{
	const bst_cfg_http *hc = c->hc;
	if (c->cur == NULL) {
		c->cur = stream_new(c);
		if (c->cur == NULL) {
			h1c_close(c);
			return b->len;
		}
		bst_h1_parser_init(&c->parser, c->cur->s.arena);
		bst_loop_timer_arm(c->loop, &c->t_head, hc->client_header_timeout_ms, on_head_timeout, c);
	}
	h1s *s = c->cur;
	const char *in = (const char *)b->data + off;
	size_t avail = b->len - off, old = c->hlen, maxh = hc->large_client_header_buffers;
	const char *base = in;
	size_t n = avail;
	if (old > 0) {
		size_t room = maxh + 1 > old ? maxh + 1 - old : 0;
		if (!hbuf_append(c, in, avail < room ? avail : room)) {
			h1c_close(c);
			return b->len;
		}
		base = c->hbuf;
		n = c->hlen;
	}
	bst_h1_limits lim = { .max_uri = hc->client_max_uri_size,
			      .max_head = maxh,
			      .max_headers = hc->client_max_header_count,
			      .allow_bare_lf = hc->http1_allow_bare_lf };
	bst_h1_result r = bst_h1_parse_head(&c->parser, base, n, &lim, &s->s.req.head);
	if (r.kind == BST_H1_NEED_MORE) {
		if (old == 0 && !hbuf_append(c, in, avail < maxh + 1 ? avail : maxh + 1)) {
			h1c_close(c);
			return b->len;
		}
		return b->len;
	}
	if (r.kind == BST_H1_ERROR) {
		reject(c, s, r.status, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 }, false);
		return b->len;
	}
	size_t used = base == in ? r.consumed : (r.consumed > old ? r.consumed - old : 0);
	head_done(c, s);
	return off + used;
}

static void on_head_timeout(void *ud)
{
	h1c *c = ud;
	h1c_enter(c);
	if (!c->closed) {
		if (!c->lingering && c->cur != NULL && c->hlen > 0) {
			h1s *s = c->cur;
			reject(c, s, 408, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 }, false);
		} else {
			h1c_close(c); /* idle keep-alive, a silent client, or the end of a lingering close */
		}
	}
	h1c_leave(c);
}

/* ---- reading ---- */

static void consume(h1c *c, bst_buf *b, size_t off)
{
	while (off < b->len && !c->closed) {
		if (c->mode == M_DISCARD)
			return;
		if (c->mode == M_HEAD) {
			if (c->no_more) {
				c->mode = M_DISCARD;
				c->unread = true;
				return;
			}
			if (c->nq >= c->hc->http1_max_pipeline) {
				c->held = bst_buf_ref(b);
				c->held_off = off;
				return;
			}
			off = head_step(c, b, off);
		} else {
			off = body_step(c, b, off);
		}
	}
}

void h1c_update_recv(h1c *c)
{
	if (c->closed)
		return;
	bool want = true;
	if (!c->lingering) {
		if (c->held != NULL)
			want = false;
		else if (c->mode == M_BODY && c->body_s != NULL && c->body_s->in.len > 0 &&
			 c->body_s->credit == 0)
			want = false;
		else if (c->mode == M_HEAD && c->nq >= c->hc->http1_max_pipeline)
			want = false;
	}
	if (want && !c->recv_on) {
		if (c->t->ops->recv_start(c->t, on_recv, c) == 0)
			c->recv_on = true;
	} else if (!want && c->recv_on) {
		(void)c->t->ops->recv_stop(c->t);
		c->recv_on = false;
	}
}

static void on_recv(void *ud, bst_buf *data, int err)
{
	h1c *c = ud;
	h1c_enter(c);
	if (data == NULL || err != 0) {
		c->recv_on = false;
		h1c_close(c);
		h1c_leave(c);
		return;
	}
	if (!c->lingering) {
		if (c->mode == M_HEAD && c->nq == 0 && c->cur == NULL && c->hlen == 0)
			bst_timer_cancel(&c->t_head); /* the idle wait is over; head_step arms the head deadline */
		consume(c, data, 0);
	}
	bst_buf_unref(data);
	h1c_update_recv(c);
	h1c_leave(c);
}

/* ---- start and stop ---- */

int bst_conn_h1_start(bst_worker *w, bst_transport *t, const bst_listener_set *set,
		      const bst_sockaddr *peer)
{
	h1c *c = calloc(1, sizeof *c);
	if (c == NULL || bst_vhost_default(set) == NULL) {
		free(c);
		t->ops->close(t);
		return -1;
	}
	if (g_slab == NULL)
		g_slab = bst_chain_slab_new(64);
	if (g_slab == NULL) {
		free(c);
		t->ops->close(t);
		return -1;
	}
	c->w = w;
	c->loop = bst_worker_loop(w);
	c->t = t;
	c->set = set;
	if (peer != NULL) {
		c->peer = *peer;
		c->has_peer = true;
	}
	c->hc = &bst_vhost_default(set)->common.http;
	c->mode = M_HEAD;
	bst_chain_init(&c->wchain, g_slab);
	bst_timer_init(&c->t_head);
	bst_timer_init(&c->t_body);
	bst_timer_init(&c->t_send);
	bst_timer_init(&c->t_flush);
	c->next = g_conns;
	if (g_conns != NULL)
		g_conns->prev = c;
	g_conns = c;
	bst_worker_conn_opened(w);
	h1c_enter(c);
	bst_loop_timer_arm(c->loop, &c->t_head, c->hc->client_header_timeout_ms, on_head_timeout, c);
	h1c_update_recv(c);
	if (!c->recv_on)
		h1c_close(c);
	h1c_leave(c);
	return 0;
}

typedef struct set_cache {
	const bst_cfg_listen *l;
	bst_listener_set *set;
	struct set_cache *next;
} set_cache;

static set_cache *g_sets;

static const bst_listener_set *set_for(bst_worker *w, const bst_cfg_listen *l)
{
	for (set_cache *e = g_sets; e != NULL; e = e->next)
		if (e->l == l)
			return e->set;
	set_cache *e = calloc(1, sizeof *e);
	if (e == NULL)
		return NULL;
	e->set = bst_vhost_set_new(bst_worker_config(w), l);
	if (e->set == NULL) {
		free(e);
		return NULL;
	}
	e->l = l;
	e->next = g_sets;
	g_sets = e;
	return e->set;
}

typedef struct tls_pending {
	bst_worker *w;
	const bst_listener_set *set;
	bst_sockaddr peer;
	bool has_peer;
} tls_pending;

static void tls_ready(void *ud, bst_transport *t)
{
	tls_pending *p = ud;
	if (t != NULL)
		(void)bst_conn_h1_start(p->w, t, p->set, p->has_peer ? &p->peer : NULL);
	free(p);
}

void bst_h1_on_conn(bst_worker *w, int fd, const bst_sockaddr *peer, const bst_cfg_listen *l)
{
	const bst_listener_set *set = set_for(w, l);
	if (l->tls && set != NULL) {
		const bst_cfg_tls *tc = &bst_vhost_default(set)->tls;
		tls_pending *p = tc->ctx != NULL ? calloc(1, sizeof *p) : NULL;
		if (p == NULL) {
			close(fd);
			return;
		}
		p->w = w;
		p->set = set;
		if (peer != NULL) {
			p->peer = *peer;
			p->has_peer = true;
		}
		if (bst_tls_accept(bst_worker_loop(w), fd, tc->ctx, tc->profile, set, tc->http_on_tls, tls_ready, p) != 0)
			free(p);
		return;
	}
	bst_sock *s = set != NULL ? bst_sock_wrap(bst_worker_loop(w), fd) : NULL;
	bst_transport *t = s != NULL ? bst_transport_plain(s) : NULL;
	if (t == NULL) {
		if (s != NULL)
			bst_sock_close(s);
		else
			close(fd);
		return;
	}
	(void)bst_conn_h1_start(w, t, set, peer);
}

void bst_h1_drain(bst_worker *w)
{
	(void)w;
	h1c *nx;
	for (h1c *c = g_conns; c != NULL; c = nx) {
		nx = c->next;
		h1c_enter(c);
		c->draining = true;
		c->no_more = true;
		if (c->nq == 0 && c->cur == NULL && !c->lingering)
			h1c_close(c);
		else if (c->tail != NULL && !c->tail->head_ready)
			c->tail->close_after = true;
		h1c_leave(c);
	}
}

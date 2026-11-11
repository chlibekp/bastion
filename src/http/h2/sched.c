/* The HTTP/2 write path: which stream's data goes next, and the one write in flight.
 *
 * Output is a single chain per write: first the control frames and header blocks queued since the
 * last write (they are encoded in wire order, which HPACK needs), then DATA frames chosen by the
 * RFC 9218 scheduler. A DATA frame is its 9-byte head (a slice of one small buffer made for the
 * round) followed by a slice taken from the stream's own body chain, so file segments stay file
 * segments and a TLS or plain transport can still send them without copying.
 *
 * Scheduling (RFC 9218 section 4). Eight urgency levels, 0 first. Within a level, a stream that is
 * not incremental is served until it is done or blocked (the order in which they became ready),
 * and incremental streams share the level frame by frame in round-robin. A round writes at most
 * http2_write_chunk bytes of DATA, so a high-urgency stream that becomes ready waits for at most
 * one chunk. */
#include "http/h2/conn_priv.h"

#include "core/log.h"

#include <string.h>

#define ROUND_FRAMES 256u /* DATA frames in one write; sizes the head buffer */

/* ---- ready lists ---- */

static void ready_add(h2s *s)
{
	h2c *c = s->c;
	unsigned u = s->urgency;
	s->rnext = NULL;
	s->rprev = c->rtail[u];
	if (c->rtail[u] != NULL)
		c->rtail[u]->rnext = s;
	else
		c->rhead[u] = s;
	c->rtail[u] = s;
	s->in_ready = true;
}

static void ready_del(h2s *s)
{
	h2c *c = s->c;
	unsigned u = s->urgency;
	if (!s->in_ready)
		return;
	if (s->rprev != NULL)
		s->rprev->rnext = s->rnext;
	else
		c->rhead[u] = s->rnext;
	if (s->rnext != NULL)
		s->rnext->rprev = s->rprev;
	else
		c->rtail[u] = s->rprev;
	s->rnext = s->rprev = NULL;
	s->in_ready = false;
}

void h2_sched_remove(h2s *s)
{
	ready_del(s);
}

static void on_stall_timer(void *ud);

static void mark_stall(h2s *s)
{
	h2c *c = s->c;
	if (s->stall_ms == 0)
		s->stall_ms = bst_loop_now_ms(c->loop) + 1;
	if (!c->stall_armed && !c->closed) {
		uint64_t tick = c->hc->send_timeout_ms;
		if (tick > 1000)
			tick = 1000;
		if (tick < 10)
			tick = 10;
		c->stall_armed = true;
		bst_loop_timer_arm(c->loop, &c->t_stall, tick, on_stall_timer, c);
	}
}

/* A stream may send when its response head is out and it has body the window lets through, or only
 * the end of the response is left (an empty DATA frame, which needs no window). */
void h2_sched_update(h2s *s)
{
	if (s->dead) {
		ready_del(s);
		return;
	}
	bool want;
	if (!s->head_sent)
		want = false;
	else if (s->out.len > 0)
		want = s->send_win > 0;
	else
		want = s->resp_done && !s->end_queued && !s->trailers_due;
	if (s->out.len > 0 && s->send_win <= 0)
		mark_stall(s);
	if (want && !s->in_ready)
		ready_add(s);
	else if (!want && s->in_ready)
		ready_del(s);
	if (want)
		h2c_arm_flush(s->c);
}

/* ---- Priority field (RFC 9218 section 5) ---- */

void h2_set_priority(h2s *s, const char *v, size_t n)
{
	uint8_t urgency = H2_DEFAULT_URGENCY;
	bool inc = false;
	size_t i = 0;
	while (i < n) {
		while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ','))
			i++;
		size_t b = i;
		while (i < n && v[i] != ',')
			i++;
		size_t e = i;
		while (e > b && (v[e - 1] == ' ' || v[e - 1] == '\t'))
			e--;
		if (e - b >= 3 && v[b] == 'u' && v[b + 1] == '=' && e - b == 3 && v[b + 2] >= '0' && v[b + 2] <= '7')
			urgency = (uint8_t)(v[b + 2] - '0');
		else if (e - b == 1 && v[b] == 'i')
			inc = true;
		else if (e - b == 4 && memcmp(v + b, "i=?1", 4) == 0)
			inc = true;
		else if (e - b == 4 && memcmp(v + b, "i=?0", 4) == 0)
			inc = false;
	}
	bool was = s->in_ready;
	if (was)
		ready_del(s);
	s->urgency = urgency;
	s->incremental = inc;
	if (was)
		ready_add(s);
}

/* ---- callbacks that are due without a write ---- */

void h2c_cbq_push(h2s *s)
{
	if (s->in_cbq || s->dead)
		return;
	s->in_cbq = true;
	s->cnext = s->c->cbq;
	s->c->cbq = s;
	h2c_arm_flush(s->c);
}

static void fire(h2s *s)
{
	if (s->dead || s->cb == NULL || s->out.len > 0 || s->in_batch)
		return;
	bst_done_cb cb = s->cb;
	void *ud = s->cb_ud;
	s->cb = NULL;
	cb(ud, 0, 0);
}

static void fire_cbq(h2c *c)
{
	while (c->cbq != NULL && !c->closed) {
		h2s *s = c->cbq;
		c->cbq = s->cnext;
		s->cnext = NULL;
		s->in_cbq = false;
		fire(s);
	}
}

/* ---- trailers ---- */

static void emit_trailers_cb(h2s *s, void *arg)
{
	(void)arg;
	h2c *c = s->c;
	if (!s->trailers_due || s->out.len > 0 || s->in_batch || s->cb != NULL)
		return;
	/* The trailer section is the end of the response: HEADERS with END_STREAM. */
	size_t before = c->ctl.len;
	bst_h2_wr blk = { 0 };
	int rc = bst_hpack_encode(&c->enc, &s->resp_trailers, &blk);
	if (rc == 0)
		rc = bst_h2_write_headers(&c->ctl, s->id, blk.p, blk.len, true, c->peer_max_frame);
	bst_h2_wr_free(&blk);
	if (rc != 0) {
		c->ctl.len = before;
		h2c_conn_error(c, BST_H2_INTERNAL_ERROR);
		return;
	}
	s->trailers_due = false;
	s->end_queued = true;
	s->local_closed = true;
	if (c->trailers_pending > 0)
		c->trailers_pending--;
	s->in_batch = true; /* so that the stream is finished once this write completes */
	s->wnext = c->batch;
	c->batch = s;
}

/* ---- the write ---- */

typedef struct round {
	h2c *c;
	bst_buf *hb;
	size_t hoff;
	uint32_t budget;
	unsigned frames;
	bool failed;
} round;

static bool add_mem(bst_chain *ch, bst_buf *b, size_t off, size_t len)
{
	return bst_chain_add_mem(ch, b, off, len) == 0;
}

/* One DATA frame from s. False when s has nothing it can send (it is then off the ready list
 * unless the round is merely out of room). */
static bool emit(round *r, h2s *s)
{
	h2c *c = r->c;
	uint64_t avail = s->out.len;
	uint32_t n = 0;
	bool end;
	if (avail == 0) { /* only the end of the response is left */
		if (!(s->resp_done && !s->end_queued && !s->trailers_due)) {
			ready_del(s);
			return false;
		}
		end = true;
	} else {
		if (s->send_win <= 0) {
			ready_del(s);
			mark_stall(s);
			return false;
		}
		if (c->send_win <= 0 || r->budget == 0 || r->frames >= ROUND_FRAMES)
			return false;
		uint64_t m = avail;
		if (m > c->peer_max_frame)
			m = c->peer_max_frame;
		if (m > (uint64_t)s->send_win)
			m = (uint64_t)s->send_win;
		if (m > (uint64_t)c->send_win)
			m = (uint64_t)c->send_win;
		if (m > r->budget)
			m = r->budget;
		n = (uint32_t)m;
		end = n == avail && s->resp_done && !s->trailers_due;
	}
	if (r->frames >= ROUND_FRAMES)
		return false;
	bst_h2_put_head(r->hb->data + r->hoff, n, BST_H2_DATA, end ? BST_H2_F_END_STREAM : 0, s->id);
	if (!add_mem(&c->wchain, r->hb, r->hoff, BST_H2_FRAME_HDR) ||
	    (n > 0 && bst_chain_take(&c->wchain, &s->out, n) != 0)) {
		r->failed = true;
		return false;
	}
	r->hoff += BST_H2_FRAME_HDR;
	r->frames++;
	if (n > 0) {
		s->send_win -= n;
		c->send_win -= n;
		r->budget -= n;
		/* Substantial progress ends a stall; one byte at a time (a window drip) does not. */
		uint64_t floor = c->peer_max_frame / 16;
		if (n >= (avail < floor ? avail : floor))
			s->stall_ms = 0;
	}
	if (!s->in_batch) {
		s->in_batch = true;
		s->wnext = c->batch;
		c->batch = s;
	}
	if (end) {
		s->end_queued = true;
		s->local_closed = true;
		s->stall_ms = 0;
		ready_del(s);
	} else if (s->out.len == 0) {
		ready_del(s);
	}
	return true;
}

static bool run_level(round *r, unsigned u)
{
	h2c *c = r->c;
	bool any = false, again;
	do {
		again = false;
		unsigned cnt = 0;
		for (h2s *s = c->rhead[u]; s != NULL; s = s->rnext)
			cnt++;
		h2s *s = c->rhead[u];
		for (unsigned i = 0; i < cnt && s != NULL && !r->failed; i++) {
			h2s *next = s->rnext;
			if (s->incremental) {
				if (emit(r, s)) {
					again = any = true;
					if (s->in_ready) { /* rotate: the others get their turn */
						ready_del(s);
						ready_add(s);
					}
				}
			} else {
				while (s->in_ready && !r->failed && emit(r, s))
					again = any = true;
			}
			s = next;
		}
	} while (again && !r->failed && r->budget > 0 && r->frames < ROUND_FRAMES && c->send_win > 0);
	return any;
}

static void on_written(void *ud, size_t bytes, int err);

static void send_timeout_cb(void *ud)
{
	h2c *c = ud;
	h2c_enter(c);
	bst_log(BST_LOG_DEBUG, "h2: send below send_min_rate, closing");
	h2c_close(c);
	h2c_leave(c);
}

static void linger_cb(void *ud)
{
	h2c *c = ud;
	h2c_enter(c);
	h2c_close(c);
	h2c_leave(c);
}

static void arm_send(h2c *c, uint64_t bytes)
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

/* The connection has finished its business: the last frames (a GOAWAY) are out. */
static void finish_dying(h2c *c)
{
	if (c->closed)
		return;
	if (c->hc->lingering_close && !c->lingering) {
		c->lingering = true;
		bst_timer_cancel(&c->t_idle);
		bst_timer_cancel(&c->t_settings);
		bst_timer_cancel(&c->t_stall);
		c->t->ops->shutdown(c->t, NULL, NULL);
		bst_loop_timer_arm(c->loop, &c->t_ling, c->hc->lingering_timeout_ms, linger_cb, c);
	} else {
		h2c_close(c);
	}
}

void h2c_pump(h2c *c)
{
	if (c->closed || c->writing || c->lingering)
		return;
	h2c_enter(c);
	if (!c->dying && c->trailers_pending > 0)
		h2s_each(c, emit_trailers_cb, NULL);
	bst_chain_clear(&c->wchain);
	if (c->ctl.len > 0) {
		bst_buf *b = bst_buf_new(c->ctl.len);
		bool ok = b != NULL;
		if (ok) {
			memcpy(b->data, c->ctl.p, c->ctl.len);
			b->len = c->ctl.len;
			ok = add_mem(&c->wchain, b, 0, c->ctl.len);
			bst_buf_unref(b);
		}
		if (!ok) {
			h2c_close(c);
			h2c_leave(c);
			return;
		}
		c->ctl.len = 0;
	}
	if (!c->dying) {
		round r = { .c = c, .budget = c->cfg->write_chunk };
		bool have = false;
		for (unsigned u = 0; u < H2_URGENCIES; u++)
			if (c->rhead[u] != NULL)
				have = true;
		if (have && c->send_win <= 0) { /* the whole connection waits on the peer's window */
			for (unsigned u = 0; u < H2_URGENCIES; u++)
				for (h2s *s = c->rhead[u]; s != NULL; s = s->rnext)
					if (s->out.len > 0)
						mark_stall(s);
		}
		if (have) {
			r.hb = bst_buf_new(BST_H2_FRAME_HDR * ROUND_FRAMES);
			if (r.hb == NULL) {
				h2c_close(c);
				h2c_leave(c);
				return;
			}
			r.hb->len = r.hb->cap; /* slices of it are what the chain refers to */
			for (unsigned u = 0; u < H2_URGENCIES && !r.failed && r.frames < ROUND_FRAMES; u++)
				(void)run_level(&r, u);
			bst_buf_unref(r.hb);
			if (r.failed) {
				h2c_close(c);
				h2c_leave(c);
				return;
			}
		}
	}
	if (bst_chain_len(&c->wchain) == 0) {
		if (c->dying) {
			finish_dying(c);
		} else {
			fire_cbq(c);
			h2c_arm_idle(c);
		}
		h2c_leave(c);
		return;
	}
	c->writing = true;
	arm_send(c, bst_chain_len(&c->wchain));
	if (c->t->ops->send(c->t, &c->wchain, on_written, c) != 0) {
		c->writing = false;
		h2c_close(c);
	}
	h2c_leave(c);
}

static void on_written(void *ud, size_t bytes, int err)
{
	(void)bytes;
	h2c *c = ud;
	h2c_enter(c);
	c->writing = false;
	bst_timer_cancel(&c->t_send);
	if (err != 0) {
		h2c_close(c);
		h2c_leave(c);
		return;
	}
	bst_chain_clear(&c->wchain);
	/* The streams of this write: first they all leave the batch, then each is looked at, so a
	 * callback that starts the next write cannot be confused with this one. */
	h2s *list = c->batch;
	c->batch = NULL;
	for (h2s *s = list; s != NULL; s = s->wnext)
		s->in_batch = false;
	while (list != NULL && !c->closed) {
		h2s *s = list;
		list = s->wnext;
		s->wnext = NULL;
		if (s->dead)
			continue;
		if (s->end_queued) {
			h2s_check_done(s);
			continue;
		}
		fire(s);
	}
	if (!c->closed) {
		fire_cbq(c);
		h2c_pump(c);
		if (c->depth == 1)
			h2c_reap(c);
	}
	h2c_leave(c);
}

/* ---- timers ---- */

static void on_flush(void *ud)
{
	h2c *c = ud;
	h2c_enter(c);
	c->flush_armed = false;
	fire_cbq(c);
	h2c_pump(c);
	if (c->depth == 1)
		h2c_reap(c);
	h2c_leave(c);
}

void h2c_arm_flush(h2c *c)
{
	if (c->flush_armed || c->closed)
		return;
	c->flush_armed = true;
	bst_loop_timer_arm(c->loop, &c->t_flush, 1, on_flush, c);
}

typedef struct stall_ctx {
	uint64_t now, limit;
	bool any;
} stall_ctx;

static void stall_check(h2s *s, void *arg)
{
	stall_ctx *x = arg;
	if (s->stall_ms == 0)
		return;
	if (s->out.len == 0) {
		s->stall_ms = 0;
		return;
	}
	if (x->now + 1 - s->stall_ms >= x->limit) {
		bst_log(BST_LOG_DEBUG, "h2: stream %u waited too long for flow-control credit", s->id);
		h2s_reset(s, BST_H2_CANCEL, BST_STREAM_ERR_TIMEOUT);
		return;
	}
	x->any = true;
}

void h2c_on_stall_timer(h2c *c)
{
	stall_ctx x = { bst_loop_now_ms(c->loop), c->hc->send_timeout_ms, false };
	c->stall_armed = false;
	h2s_each(c, stall_check, &x);
	if (x.any && !c->closed) {
		c->stall_armed = true;
		uint64_t tick = c->hc->send_timeout_ms > 1000 ? 1000 : c->hc->send_timeout_ms;
		bst_loop_timer_arm(c->loop, &c->t_stall, tick < 10 ? 10 : tick, on_stall_timer, c);
	}
	h2c_arm_flush(c);
}

static void on_stall_timer(void *ud)
{
	h2c *c = ud;
	h2c_enter(c);
	h2c_on_stall_timer(c);
	h2c_leave(c);
}

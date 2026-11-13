/* See client_h2.h. One connection object (h2up) per upstream TCP or TLS connection, kept on a
 * per-process list; streams (bst_h2us) hang off it in the order they were opened.
 *
 * Writes. Control frames and HEADERS are appended to c->ctl as they arise; DATA frames are cut
 * from the streams' queued bytes at flush time under both windows. One write is outstanding at a
 * time: it carries the control bytes first, then DATA frames whose payload segments are moved
 * (not copied) from the streams' chains.
 *
 * Lifetime. A stream object lives until the caller released it AND the connection is done with
 * it; callbacks run under a busy count on both the stream and the connection, so a release or a
 * connection failure from inside a callback is finished by the outermost frame. */
#include "proxy/client_h2.h"

#include "core/log.h"
#include "http/h2/frame.h"
#include "http/h2/hpack.h"
#include "http/token.h"
#include "proxy/pool.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define OUR_MAX_FRAME BST_H2_MIN_FRAME
#define OUR_STREAM_WINDOW (256u * 1024u)
#define OUR_CONN_WINDOW (16u * 1024u * 1024u)
#define FLUSH_BUDGET (256u * 1024u)
#define FLUSH_FRAMES 64u
#define MAX_HEADER_BLOCK (256u * 1024u)

static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

typedef struct h2up h2up;

struct bst_h2us {
	h2up *c; /* NULL once the connection is done with it */
	uint32_t id;
	bool started, local_end, remote_end, head_done, body;
	bool released, want_sent, closed;
	unsigned busy;
	bst_arena *arena; /* the request fields until sent, the decoded heads */
	bst_headers req;
	bst_chain out;
	bool out_end;
	int64_t send_win;
	uint32_t unacked; /* consumed bytes not yet given back in a WINDOW_UPDATE */
	const bst_h2us_ops *ops;
	void *ud;
	struct deferred_fail *df; /* a failure waiting for the loop (no connection at all) */
	bst_h2us *next, *prev;
};

struct h2up {
	bst_loop *loop;
	const bst_cfg_upstream *up;
	const bst_peer *peer;
	bst_sockaddr addr;
	bst_upconn *uc;
	bool connecting, ready, goaway, closed, sending;
	uint32_t next_id, last_ok; /* last_ok: the peer's GOAWAY last-stream-id */
	uint32_t peer_max_streams, peer_max_frame, peer_init_win;
	int64_t send_win;
	uint32_t recv_unacked;
	unsigned nactive, nwaiting;
	bst_hpack_enc enc;
	bst_hpack_dec dec;
	uint8_t *rbuf;
	size_t rlen, rcap;
	uint8_t *hblk; /* a header block being assembled from HEADERS and CONTINUATION */
	size_t hlen, hcap;
	uint32_t hstream;
	bool hend, in_block;
	bst_h2_wr ctl;
	bst_chain wq; /* the write in flight */
	bst_timer idle;
	unsigned busy;
	bst_h2us *head, *tail;
	h2up *gnext, *gprev;
};

static h2up *g_conns;
static bst_slab *g_slab;

static bst_slab *slab(void)
{
	if (g_slab == NULL)
		g_slab = bst_chain_slab_new(256);
	return g_slab;
}

/* ---- lifetimes ---- */

static void conn_free(h2up *c)
{
	bst_timer_cancel(&c->idle);
	if (c->uc != NULL)
		bst_pool_close(c->uc);
	bst_chain_clear(&c->wq);
	if (c->gprev != NULL)
		c->gprev->gnext = c->gnext;
	else if (g_conns == c)
		g_conns = c->gnext;
	if (c->gnext != NULL)
		c->gnext->gprev = c->gprev;
	bst_hpack_enc_free(&c->enc);
	bst_hpack_dec_free(&c->dec);
	bst_h2_wr_free(&c->ctl);
	free(c->rbuf);
	free(c->hblk);
	free(c);
}

static void conn_enter(h2up *c)
{
	c->busy++;
}

static void conn_leave(h2up *c)
{
	if (--c->busy == 0 && c->closed)
		conn_free(c);
}

static void st_free(bst_h2us *st)
{
	bst_chain_clear(&st->out);
	bst_arena_free(st->arena);
	free(st);
}

static void st_enter(bst_h2us *st)
{
	st->busy++;
}

static void st_leave(bst_h2us *st)
{
	if (--st->busy == 0 && st->released && st->c == NULL)
		st_free(st);
}

static void arm_idle(h2up *c);
static void kick(h2up *c);

/* The connection is done with the stream. */
static void st_unlink(bst_h2us *st)
{
	h2up *c = st->c;
	if (c == NULL)
		return;
	if (st->prev != NULL)
		st->prev->next = st->next;
	else
		c->head = st->next;
	if (st->next != NULL)
		st->next->prev = st->prev;
	else
		c->tail = st->prev;
	if (st->started)
		c->nactive--;
	else
		c->nwaiting--;
	st->c = NULL;
	st->closed = true;
	bst_chain_clear(&st->out);
	if (!c->closed) {
		if (c->goaway && c->nactive == 0 && c->nwaiting == 0)
			c->closed = true; /* drained: conn_leave frees it */
		else if (c->nactive == 0 && c->nwaiting == 0)
			arm_idle(c);
		else
			kick(c); /* a slot opened for a waiting stream */
	}
	if (st->released && st->busy == 0)
		st_free(st);
}

static void st_error(bst_h2us *st, int err, int kind)
{
	st_enter(st);
	st_unlink(st);
	if (!st->released && st->ops->on_error != NULL)
		st->ops->on_error(st->ud, err, kind);
	st_leave(st);
}

/* The connection failed: every stream on it fails; one never started was not sent at all. */
static void conn_fail(h2up *c, int err, bool connect)
{
	if (c->closed)
		return;
	conn_enter(c);
	c->closed = true;
	if (c->uc != NULL) {
		bst_pool_close(c->uc);
		c->uc = NULL;
	}
	while (c->head != NULL) {
		bst_h2us *st = c->head;
		int kind = connect ? BST_H2US_CONNECT : st->started ? BST_H2US_FAILED : BST_H2US_REFUSED;
		/* st_unlink keeps the closed connection as it is */
		st_error(st, err, kind);
	}
	conn_leave(c);
}

/* A connection error of ours: GOAWAY with code, then close. */
static void conn_error(h2up *c, uint32_t code)
{
	bst_log(BST_LOG_WARN, "proxy: HTTP/2 upstream %s: protocol error %u: closing the connection",
		c->up->name, code);
	/* the connection closes at once (no GOAWAY: a write would race the close); the peer sees
	 * the transport end, and every stream on it fails */
	conn_fail(c, -EPROTO, false);
}

static void on_idle(void *ud)
{
	h2up *c = ud;
	conn_enter(c);
	if (c->nactive == 0 && c->nwaiting == 0)
		conn_fail(c, -ECONNRESET, false);
	conn_leave(c);
}

static void arm_idle(h2up *c)
{
	bst_loop_timer_arm(c->loop, &c->idle, c->up->keepalive_timeout_ms, on_idle, c);
}

/* ---- writing ---- */

static uint32_t stream_limit(const h2up *c)
{
	uint32_t lim = c->up->h2_max_streams ? c->up->h2_max_streams : 100;
	return c->peer_max_streams < lim ? c->peer_max_streams : lim;
}

static void on_written(void *ud, size_t bytes, int err);

/* The HEADERS of a waiting stream go out now: it gets the next id. */
static int start_stream(h2up *c, bst_h2us *st)
{
	bst_h2_wr blk = { 0 };
	if (bst_hpack_encode(&c->enc, &st->req, &blk) != 0) {
		bst_h2_wr_free(&blk);
		return -1;
	}
	st->id = c->next_id;
	c->next_id += 2;
	st->started = true;
	c->nwaiting--;
	c->nactive++;
	st->send_win = c->peer_init_win;
	int rc = bst_h2_write_headers(&c->ctl, st->id, blk.p, blk.len, !st->body, c->peer_max_frame);
	bst_h2_wr_free(&blk);
	if (rc != 0)
		return -1;
	if (!st->body)
		st->local_end = true;
	return 0;
}

static void kick(h2up *c)
{
	if (c->closed || c->connecting || c->uc == NULL || c->sending)
		return;
	conn_enter(c);
	if (c->ready && !c->goaway) {
		for (bst_h2us *st = c->head; st != NULL && c->nactive < stream_limit(c);) {
			bst_h2us *nx = st->next;
			if (!st->started && start_stream(c, st) != 0) {
				conn_error(c, BST_H2_INTERNAL_ERROR);
				goto out;
			}
			st = nx;
		}
	}
	bst_chain *ch = &c->wq; /* empty while no write is out; the send keeps a pointer to it */
	if (c->ctl.len > 0) {
		bst_buf *b = bst_buf_new(c->ctl.len);
		if (b == NULL) {
			conn_fail(c, -ENOMEM, false);
			goto out;
		}
		memcpy(b->data, c->ctl.p, c->ctl.len);
		b->len = c->ctl.len;
		int rc = bst_chain_add_mem(ch, b, 0, b->len);
		bst_buf_unref(b);
		c->ctl.len = 0;
		if (rc != 0) {
			bst_chain_clear(ch);
			conn_fail(c, -ENOMEM, false);
			goto out;
		}
	}
	bst_buf *heads = bst_buf_new(FLUSH_FRAMES * BST_H2_FRAME_HDR);
	if (heads == NULL) {
		bst_chain_clear(ch);
		conn_fail(c, -ENOMEM, false);
		goto out;
	}
	size_t budget = FLUSH_BUDGET, frames = 0;
	bool progress = true;
	while (progress && budget > 0 && frames < FLUSH_FRAMES) {
		progress = false;
		for (bst_h2us *st = c->head; st != NULL && budget > 0 && frames < FLUSH_FRAMES;
		     st = st->next) {
			if (!st->started || st->local_end)
				continue;
			uint64_t have = bst_chain_len(&st->out);
			if (have == 0 && !st->out_end)
				continue;
			int64_t win = st->send_win < c->send_win ? st->send_win : c->send_win;
			uint64_t n = have;
			if (n > c->peer_max_frame)
				n = c->peer_max_frame;
			if (n > budget)
				n = budget;
			if (win < 0)
				win = 0;
			if (n > (uint64_t)win)
				n = (uint64_t)win;
			bool end = st->out_end && n == have;
			if (n == 0 && !end)
				continue;
			size_t hoff = heads->len;
			bst_h2_put_head(heads->data + hoff, (uint32_t)n, BST_H2_DATA,
					end ? BST_H2_F_END_STREAM : 0, st->id);
			heads->len += BST_H2_FRAME_HDR;
			if (bst_chain_add_mem(ch, heads, hoff, BST_H2_FRAME_HDR) != 0 ||
			    (n > 0 && bst_chain_take(ch, &st->out, n) != 0)) {
				bst_buf_unref(heads);
				bst_chain_clear(ch);
				conn_fail(c, -ENOMEM, false);
				goto out;
			}
			frames++;
			st->send_win -= (int64_t)n;
			c->send_win -= (int64_t)n;
			budget -= (size_t)n;
			if (end)
				st->local_end = true;
			progress = true;
		}
	}
	bst_buf_unref(heads);
	if (bst_chain_len(ch) == 0)
		goto out;
	c->sending = true;
	if (bst_upconn_send(c->uc, ch, on_written, c) != 0) {
		c->sending = false;
		bst_chain_clear(ch);
		conn_fail(c, -EIO, false);
		goto out;
	}
out:
	conn_leave(c);
}

static void on_written(void *ud, size_t bytes, int err)
{
	h2up *c = ud;
	(void)bytes;
	conn_enter(c);
	c->sending = false;
	if (c->closed)
		goto out;
	if (err != 0) {
		conn_fail(c, err, false);
		goto out;
	}
	for (bst_h2us *st = c->head; st != NULL && !c->closed;) {
		bst_h2us *nx = st->next;
		if (st->want_sent && bst_chain_len(&st->out) == 0 && !st->released) {
			st->want_sent = false;
			st_enter(st);
			if (st->ops->on_sent != NULL)
				st->ops->on_sent(st->ud);
			nx = st->c == c ? st->next : c->head; /* st may have left the list */
			st_leave(st);
		}
		st = nx;
	}
	kick(c);
out:
	conn_leave(c);
}

/* ---- reading ---- */

static bst_h2us *find(h2up *c, uint32_t id)
{
	for (bst_h2us *st = c->head; st != NULL; st = st->next)
		if (st->started && st->id == id)
			return st;
	return NULL;
}

/* A stream error of ours: RST_STREAM, and the caller sees a failure. */
static void st_reset(h2up *c, bst_h2us *st, uint32_t code)
{
	(void)bst_h2_write_rst(&c->ctl, st->id, code);
	st_error(st, -EPROTO, BST_H2US_FAILED);
	kick(c);
}

static bool conn_specific(bst_hdr_id id)
{
	return id == BST_H_CONNECTION || id == BST_H_KEEP_ALIVE || id == BST_H_PROXY_CONNECTION ||
	       id == BST_H_TRANSFER_ENCODING || id == BST_H_UPGRADE;
}

static void stream_done_check(bst_h2us *st)
{
	if (st->c != NULL && st->remote_end) {
		if (!st->local_end) {
			/* the response ended before the request body: stop sending it */
			(void)bst_h2_write_rst(&st->c->ctl, st->id, BST_H2_NO_ERROR);
			h2up *c = st->c;
			st_unlink(st);
			kick(c);
		} else {
			st_unlink(st);
		}
	}
}

static void on_block(h2up *c, uint32_t sid, const uint8_t *blk, size_t n, bool end)
{
	bst_h2us *st = find(c, sid);
	bst_arena *tmp = NULL;
	bst_arena *a = st != NULL ? st->arena : (tmp = bst_arena_new(4096));
	if (a == NULL) {
		conn_fail(c, -ENOMEM, false);
		return;
	}
	bst_headers h;
	bst_headers_init(&h, a);
	bst_hpack_limits lim = { .max_header_list_size = 65536 };
	int rc = bst_hpack_decode(&c->dec, blk, n, a, &h, &lim);
	if (rc == BST_HPACK_ERR || rc == BST_HPACK_NOMEM) {
		if (tmp != NULL)
			bst_arena_free(tmp);
		conn_error(c, BST_H2_COMPRESSION_ERROR);
		return;
	}
	if (st == NULL) { /* a stream we already gave up: the block only kept HPACK in step */
		bst_arena_free(tmp);
		if (sid >= c->next_id || (sid & 1) == 0)
			conn_error(c, BST_H2_PROTOCOL_ERROR);
		return;
	}
	if (rc == BST_HPACK_TOO_LARGE) {
		st_reset(c, st, BST_H2_PROTOCOL_ERROR);
		return;
	}
	bst_headers reg;
	bst_headers_init(&reg, a);
	int status = -1;
	bool pseudo_ok = true, regular_seen = false;
	for (uint32_t i = 0; i < h.n; i++) {
		const bst_header *f = &h.v[i];
		if (f->name.len > 0 && f->name.p[0] == ':') {
			if (regular_seen || st->head_done || status >= 0 || f->name.len != 7 ||
			    memcmp(f->name.p, ":status", 7) != 0 || f->value.len != 3) {
				pseudo_ok = false;
				break;
			}
			status = 0;
			for (int k = 0; k < 3; k++) {
				char d = f->value.p[k];
				if (d < '0' || d > '9') {
					pseudo_ok = false;
					break;
				}
				status = status * 10 + (d - '0');
			}
			continue;
		}
		regular_seen = true;
		bool upper = false;
		for (uint32_t k = 0; k < f->name.len; k++)
			upper |= f->name.p[k] >= 'A' && f->name.p[k] <= 'Z';
		if (upper || !bst_is_token(f->name) || conn_specific(f->id) ||
		    !bst_is_field_value_clean(f->value) ||
		    (f->id == BST_H_TE && !bst_str_ieq(f->value, BST_S("trailers")))) {
			pseudo_ok = false;
			break;
		}
		if (bst_headers_add(&reg, f->name, f->value) != 0) {
			st_reset(c, st, BST_H2_INTERNAL_ERROR);
			return;
		}
	}
	if (!pseudo_ok) {
		bst_log(BST_LOG_WARN, "proxy: HTTP/2 upstream %s sent a malformed header block",
			c->up->name);
		st_reset(c, st, BST_H2_PROTOCOL_ERROR);
		return;
	}
	st_enter(st);
	if (!st->head_done) {
		if (status < 100 || status > 999 || status == 101 || (status < 200 && end)) {
			st_leave(st);
			st_reset(c, st, BST_H2_PROTOCOL_ERROR);
			return;
		}
		if (status >= 200) {
			st->head_done = true;
			if (end)
				st->remote_end = true;
			if (!st->released && st->ops->on_head != NULL)
				st->ops->on_head(st->ud, status, &reg, end);
		}
	} else {
		if (!end) { /* a second HEADERS that does not end the stream */
			st_leave(st);
			st_reset(c, st, BST_H2_PROTOCOL_ERROR);
			return;
		}
		st->remote_end = true;
		if (!st->released && st->ops->on_trailers != NULL)
			st->ops->on_trailers(st->ud, &reg);
	}
	stream_done_check(st);
	st_leave(st);
}

static void on_settings(h2up *c, const bst_h2_frame *f)
{
	if (f->flags & BST_H2_F_ACK)
		return;
	size_t pos = 0;
	uint16_t id;
	uint32_t v;
	while (bst_h2_settings_next(f, &pos, &id, &v)) {
		switch (id) {
		case BST_H2_S_HEADER_TABLE_SIZE:
			bst_hpack_enc_set_max(&c->enc, v < 4096 ? v : 4096);
			break;
		case BST_H2_S_MAX_CONCURRENT_STREAMS:
			c->peer_max_streams = v;
			break;
		case BST_H2_S_INITIAL_WINDOW_SIZE:
			if (v > BST_H2_MAX_WINDOW) {
				conn_error(c, BST_H2_FLOW_CONTROL_ERROR);
				return;
			}
			for (bst_h2us *st = c->head; st != NULL; st = st->next)
				if (st->started)
					st->send_win += (int64_t)v - (int64_t)c->peer_init_win;
			c->peer_init_win = v;
			break;
		case BST_H2_S_MAX_FRAME_SIZE:
			if (v < BST_H2_MIN_FRAME || v > BST_H2_MAX_FRAME) {
				conn_error(c, BST_H2_PROTOCOL_ERROR);
				return;
			}
			c->peer_max_frame = v;
			break;
		case BST_H2_S_ENABLE_PUSH:
			if (v > 1) {
				conn_error(c, BST_H2_PROTOCOL_ERROR);
				return;
			}
			break;
		default:
			break;
		}
	}
	(void)bst_h2_write_settings(&c->ctl, NULL, 0, true);
	c->ready = true;
}

static void on_goaway(h2up *c, const bst_h2_frame *f)
{
	c->goaway = true;
	c->last_ok = f->last_stream;
	if (f->value != BST_H2_NO_ERROR)
		bst_log(BST_LOG_INFO, "proxy: HTTP/2 upstream %s sent GOAWAY (error %u)", c->up->name,
			f->value);
	while (!c->closed) { /* the list may change in a callback: look again each time */
		bst_h2us *v = NULL;
		for (bst_h2us *st = c->head; st != NULL && v == NULL; st = st->next)
			if (!st->started || st->id > f->last_stream)
				v = st;
		if (v == NULL)
			break;
		st_error(v, -ECONNRESET, BST_H2US_REFUSED);
	}
	if (!c->closed && c->nactive == 0 && c->nwaiting == 0)
		conn_fail(c, -ECONNRESET, false);
}

static void on_data_frame(h2up *c, const bst_h2_frame *f)
{
	c->recv_unacked += f->length;
	if (c->recv_unacked >= OUR_CONN_WINDOW / 2) {
		(void)bst_h2_write_window_update(&c->ctl, 0, c->recv_unacked);
		c->recv_unacked = 0;
	}
	bst_h2us *st = find(c, f->stream_id);
	if (st == NULL) {
		if (f->stream_id >= c->next_id)
			conn_error(c, BST_H2_PROTOCOL_ERROR);
		return; /* a stream we reset: the peer had not seen it yet */
	}
	if (!st->head_done || st->remote_end) {
		st_reset(c, st, BST_H2_PROTOCOL_ERROR);
		return;
	}
	st->unacked += f->length - f->data_len; /* padding is ours to give back at once */
	bool end = (f->flags & BST_H2_F_END_STREAM) != 0;
	bst_chain ch;
	bst_chain_init(&ch, slab());
	if (f->data_len > 0) {
		bst_buf *b = bst_buf_new(f->data_len);
		if (b == NULL) {
			conn_fail(c, -ENOMEM, false);
			return;
		}
		memcpy(b->data, f->data, f->data_len);
		b->len = f->data_len;
		int rc = bst_chain_add_mem(&ch, b, 0, b->len);
		bst_buf_unref(b);
		if (rc != 0) {
			conn_fail(c, -ENOMEM, false);
			return;
		}
	}
	if (end)
		st->remote_end = true;
	st_enter(st);
	if (!st->released && st->ops->on_data != NULL)
		st->ops->on_data(st->ud, &ch, end);
	bst_chain_clear(&ch);
	stream_done_check(st);
	st_leave(st);
}

static void on_frame(h2up *c, const bst_h2_frame *f)
{
	if (c->in_block && (f->type != BST_H2_CONTINUATION || f->stream_id != c->hstream)) {
		conn_error(c, BST_H2_PROTOCOL_ERROR);
		return;
	}
	switch (f->type) {
	case BST_H2_SETTINGS:
		on_settings(c, f);
		break;
	case BST_H2_PING:
		if (!(f->flags & BST_H2_F_ACK))
			(void)bst_h2_write_ping(&c->ctl, f->ping, true);
		break;
	case BST_H2_GOAWAY:
		on_goaway(c, f);
		break;
	case BST_H2_WINDOW_UPDATE:
		if (f->stream_id == 0) {
			if (c->send_win + (int64_t)f->value > BST_H2_MAX_WINDOW) {
				conn_error(c, BST_H2_FLOW_CONTROL_ERROR);
				return;
			}
			c->send_win += f->value;
		} else {
			bst_h2us *st = find(c, f->stream_id);
			if (st != NULL) {
				if (st->send_win + (int64_t)f->value > BST_H2_MAX_WINDOW) {
					st_reset(c, st, BST_H2_FLOW_CONTROL_ERROR);
					return;
				}
				st->send_win += f->value;
			}
		}
		break;
	case BST_H2_RST_STREAM: {
		bst_h2us *st = find(c, f->stream_id);
		if (st != NULL)
			st_error(st, -ECONNRESET,
				 f->value == BST_H2_REFUSED_STREAM ? BST_H2US_REFUSED : BST_H2US_FAILED);
		break;
	}
	case BST_H2_HEADERS:
	case BST_H2_CONTINUATION:
		if (f->type == BST_H2_HEADERS) {
			c->hstream = f->stream_id;
			c->hend = (f->flags & BST_H2_F_END_STREAM) != 0;
			c->hlen = 0;
		}
		if (c->hlen + f->data_len > MAX_HEADER_BLOCK) {
			conn_error(c, BST_H2_ENHANCE_YOUR_CALM);
			return;
		}
		if (c->hlen + f->data_len > c->hcap) {
			size_t nc = c->hcap ? c->hcap : 4096;
			while (nc < c->hlen + f->data_len)
				nc *= 2;
			uint8_t *nb = realloc(c->hblk, nc);
			if (nb == NULL) {
				conn_fail(c, -ENOMEM, false);
				return;
			}
			c->hblk = nb;
			c->hcap = nc;
		}
		if (f->data_len > 0)
			memcpy(c->hblk + c->hlen, f->data, f->data_len);
		c->hlen += f->data_len;
		c->in_block = !(f->flags & BST_H2_F_END_HEADERS);
		if (!c->in_block)
			on_block(c, c->hstream, c->hblk, c->hlen, c->hend);
		break;
	case BST_H2_DATA:
		on_data_frame(c, f);
		break;
	default: /* PRIORITY, PRIORITY_UPDATE and unknown types: ignored */
		break;
	}
}

static void on_recv(void *ud, bst_buf *b, int err)
{
	h2up *c = ud;
	conn_enter(c);
	if (c->closed)
		goto out;
	if (b == NULL) {
		conn_fail(c, err != 0 ? err : -ECONNRESET, false);
		goto out;
	}
	if (c->rlen + b->len > c->rcap) {
		size_t nc = c->rcap ? c->rcap : 32768;
		while (nc < c->rlen + b->len)
			nc *= 2;
		uint8_t *nb = realloc(c->rbuf, nc);
		if (nb == NULL) {
			conn_fail(c, -ENOMEM, false);
			goto out;
		}
		c->rbuf = nb;
		c->rcap = nc;
	}
	memcpy(c->rbuf + c->rlen, b->data, b->len);
	c->rlen += b->len;
	size_t pos = 0;
	while (!c->closed) {
		bst_h2_frame f;
		bst_h2_err e;
		ssize_t n = bst_h2_frame_parse(c->rbuf + pos, c->rlen - pos, OUR_MAX_FRAME, &f, &e);
		if (n == 0)
			break;
		if (n < 0) {
			if (e.stream == 0) {
				conn_error(c, e.code);
				goto out;
			}
			bst_h2us *st = find(c, e.stream);
			if (st != NULL)
				st_reset(c, st, e.code);
			/* the frame's length is in its head: skip it */
			uint32_t len = ((uint32_t)c->rbuf[pos] << 16) | ((uint32_t)c->rbuf[pos + 1] << 8) |
				       c->rbuf[pos + 2];
			if (c->rlen - pos < BST_H2_FRAME_HDR + (size_t)len) {
				conn_error(c, e.code);
				goto out;
			}
			pos += BST_H2_FRAME_HDR + len;
			continue;
		}
		if (!c->ready && f.type != BST_H2_SETTINGS) {
			conn_error(c, BST_H2_PROTOCOL_ERROR); /* the server preface is a SETTINGS frame */
			goto out;
		}
		on_frame(c, &f);
		pos += (size_t)n;
	}
	if (!c->closed) {
		memmove(c->rbuf, c->rbuf + pos, c->rlen - pos);
		c->rlen -= pos;
		kick(c);
	}
out:
	bst_buf_unref(b);
	conn_leave(c);
}

static void on_connect(void *ud, bst_upconn *uc, int err)
{
	h2up *c = ud;
	conn_enter(c);
	c->connecting = false;
	if (c->closed) {
		if (uc != NULL)
			bst_pool_close(uc);
		goto out;
	}
	if (err != 0) {
		conn_fail(c, err, true);
		goto out;
	}
	c->uc = uc;
	const uint32_t settings[][2] = {
		{ BST_H2_S_ENABLE_PUSH, 0 },
		{ BST_H2_S_INITIAL_WINDOW_SIZE, OUR_STREAM_WINDOW },
		{ BST_H2_S_MAX_HEADER_LIST_SIZE, 65536 },
	};
	if (bst_h2_wr_reserve(&c->ctl, sizeof preface - 1) != 0) {
		conn_fail(c, -ENOMEM, false);
		goto out;
	}
	memcpy(c->ctl.p + c->ctl.len, preface, sizeof preface - 1);
	c->ctl.len += sizeof preface - 1;
	if (bst_h2_write_settings(&c->ctl, settings, sizeof settings / sizeof settings[0], false) != 0 ||
	    bst_h2_write_window_update(&c->ctl, 0, OUR_CONN_WINDOW - 65535) != 0 ||
	    bst_upconn_recv_start(uc, on_recv, c) != 0) {
		conn_fail(c, -ENOMEM, false);
		goto out;
	}
	kick(c);
out:
	conn_leave(c);
}

/* ---- the API ---- */

static h2up *conn_for(bst_loop *l, const bst_cfg_upstream *u, const bst_peer *peer,
		      const bst_sockaddr *addr)
{
	for (h2up *c = g_conns; c != NULL; c = c->gnext) {
		if (c->up == u && c->peer == peer && !c->closed && !c->goaway &&
		    bst_ip_eq(&c->addr.ip, &addr->ip) && c->addr.port == addr->port &&
		    c->nactive + c->nwaiting < stream_limit(c))
			return c;
	}
	h2up *c = calloc(1, sizeof *c);
	if (c == NULL)
		return NULL;
	c->loop = l;
	c->up = u;
	c->peer = peer;
	c->addr = *addr;
	c->next_id = 1;
	c->peer_max_streams = UINT32_MAX;
	c->peer_max_frame = BST_H2_MIN_FRAME;
	c->peer_init_win = 65535;
	c->send_win = 65535;
	c->connecting = true;
	bst_timer_init(&c->idle);
	bst_chain_init(&c->wq, slab());
	bst_hpack_enc_init(&c->enc, 4096);
	bst_hpack_dec_init(&c->dec, 4096);
	c->gnext = g_conns;
	if (g_conns != NULL)
		g_conns->gprev = c;
	g_conns = c;
	bst_upconn *uc = NULL;
	int rc = bst_pool_get(l, u, peer, addr, true, on_connect, c, &uc);
	if (rc == 1) /* fresh never hands out an idle one; should it, start over cleanly */
		bst_pool_close(uc);
	if (rc != 0) {
		c->closed = true; /* the caller's stream fails from a timer, never inside open */
		c->connecting = false;
	}
	return c;
}

typedef struct deferred_fail {
	bst_timer t;
	bst_h2us *st;
} deferred_fail;

static void on_deferred_fail(void *ud)
{
	deferred_fail *d = ud;
	bst_h2us *st = d->st;
	free(d);
	st->df = NULL;
	st_enter(st);
	st->closed = true;
	if (!st->released && st->ops->on_error != NULL)
		st->ops->on_error(st->ud, -ECONNREFUSED, BST_H2US_CONNECT);
	st_leave(st);
}

bst_h2us *bst_h2us_open(bst_loop *l, const bst_cfg_upstream *u, const bst_peer *peer,
			const bst_sockaddr *addr, const bst_headers *req, bool body,
			const bst_h2us_ops *ops, void *ud)
{
	bst_h2us *st = calloc(1, sizeof *st);
	if (st == NULL)
		return NULL;
	st->arena = bst_arena_new(4096);
	if (st->arena == NULL) {
		free(st);
		return NULL;
	}
	bst_headers_init(&st->req, st->arena);
	for (uint32_t i = 0; i < req->n; i++) {
		const bst_header *f = &req->v[i];
		char *nm = bst_arena_alloc(st->arena, (size_t)f->name.len + f->value.len + 1);
		if (nm == NULL)
			goto fail;
		memcpy(nm, f->name.p, f->name.len);
		if (f->value.len > 0)
			memcpy(nm + f->name.len, f->value.p, f->value.len);
		if (bst_headers_add(&st->req, (bst_str){ nm, f->name.len },
				    (bst_str){ nm + f->name.len, f->value.len }) != 0)
			goto fail;
	}
	st->body = body;
	st->ops = ops;
	st->ud = ud;
	bst_chain_init(&st->out, slab());
	h2up *c = conn_for(l, u, peer, addr);
	if (c == NULL)
		goto fail;
	if (c->closed) {
		/* not even a socket: fail from the loop, like a refused connect */
		deferred_fail *d = calloc(1, sizeof *d);
		if (d == NULL)
			goto fail;
		if (c->busy == 0)
			conn_free(c);
		d->st = st;
		st->df = d;
		st->closed = true;
		bst_timer_init(&d->t);
		bst_loop_timer_arm(l, &d->t, 0, on_deferred_fail, d);
		return st;
	}
	st->c = c;
	st->prev = c->tail;
	if (c->tail != NULL)
		c->tail->next = st;
	else
		c->head = st;
	c->tail = st;
	c->nwaiting++;
	bst_timer_cancel(&c->idle);
	kick(c);
	return st;
fail:
	bst_arena_free(st->arena);
	free(st);
	return NULL;
}

int bst_h2us_send(bst_h2us *st, bst_chain *data, bool end)
{
	if (st->c == NULL || st->local_end || st->out_end) {
		bst_chain_clear(data);
		return -1;
	}
	if (bst_chain_move(&st->out, data) != 0) {
		bst_chain_clear(data);
		return -1;
	}
	if (end)
		st->out_end = true;
	st->want_sent = true;
	kick(st->c);
	return 0;
}

void bst_h2us_consumed(bst_h2us *st, size_t n)
{
	h2up *c = st->c;
	if (c == NULL || c->closed || st->remote_end)
		return;
	st->unacked += (uint32_t)n;
	if (st->unacked >= OUR_STREAM_WINDOW / 4) {
		(void)bst_h2_write_window_update(&c->ctl, st->id, st->unacked);
		st->unacked = 0;
		kick(c);
	}
}

void bst_h2us_release(bst_h2us *st)
{
	if (st == NULL || st->released)
		return;
	st->released = true;
	h2up *c = st->c;
	if (c != NULL) {
		if (st->started && !c->closed)
			(void)bst_h2_write_rst(&c->ctl, st->id, BST_H2_CANCEL);
		conn_enter(c);
		st_unlink(st); /* frees st when no callback of it is running */
		kick(c);
		conn_leave(c);
		return;
	}
	if (st->df != NULL) {
		bst_timer_cancel(&st->df->t);
		free(st->df);
		st->df = NULL;
	}
	if (st->busy == 0)
		st_free(st);
}

unsigned bst_h2up_conns(const bst_cfg_upstream *u)
{
	unsigned n = 0;
	for (const h2up *c = g_conns; c != NULL; c = c->gnext)
		if (c->up == u && !c->closed)
			n++;
	return n;
}

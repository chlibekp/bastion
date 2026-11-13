/* What each frame the peer sends does to the connection (RFC 9113 section 6), and the checks that
 * keep a hostile peer from making that expensive: every frame that costs us work but gives the
 * peer nothing back is charged to an abuse budget (guard.c) before it is acted on. */
#include "http/h2/conn_priv.h"

#include "core/log.h"

#include <string.h>

/* ---- header blocks ---- */

static void block_reset(h2c *c)
{
	c->hb.active = false;
	c->hb.len = 0;
	c->hb.frames = 0;
}

static bool block_append(h2c *c, const uint8_t *p, size_t n)
{
	/* The raw block is bounded by what the list limit lets through, with room for the encoding's
	 * overhead (a literal field costs a few bytes more than its text). */
	size_t limit = (size_t)c->cfg->max_header_list_size * 4u + 1024u;
	if (c->hb.len + n > limit) {
		bst_h2_guard_hit(BST_H2G_CONTINUATION);
		h2c_conn_error(c, BST_H2_ENHANCE_YOUR_CALM);
		return false;
	}
	if (c->hb.len + n > c->hb.cap) {
		size_t cap = c->hb.cap != 0 ? c->hb.cap : 1024;
		while (cap < c->hb.len + n)
			cap *= 2;
		uint8_t *q = realloc(c->hb.buf, cap);
		if (q == NULL) {
			h2c_conn_error(c, BST_H2_INTERNAL_ERROR);
			return false;
		}
		c->hb.buf = q;
		c->hb.cap = cap;
	}
	if (n > 0)
		memcpy(c->hb.buf + c->hb.len, p, n);
	c->hb.len += n;
	return true;
}

static void block_done(h2c *c)
{
	uint32_t sid = c->hb.sid;
	h2s *s = c->hb.mode == H2_HB_DISCARD ? NULL : h2s_find(c, sid);
	bst_arena *arena = s != NULL ? s->s.arena : c->scratch;
	bst_headers in;
	bst_headers_init(&in, arena);
	bst_hpack_limits lim = { .max_header_list_size = c->cfg->max_header_list_size };
	/* The block is decoded even when nobody wants it: the compression state is the connection's. */
	int rc = bst_hpack_decode(&c->dec, c->hb.buf, c->hb.len, arena, &in, &lim);
	uint8_t mode = c->hb.mode;
	bool end = c->hb.end_stream;
	block_reset(c);
	if (rc == BST_HPACK_TOO_LARGE) { /* the list limit was announced in SETTINGS: this peer ignored it */
		bst_h2_guard_hit(BST_H2G_CONTINUATION);
		h2c_conn_error(c, BST_H2_ENHANCE_YOUR_CALM);
		return;
	}
	if (rc != BST_HPACK_OK) {
		h2c_conn_error(c, rc == BST_HPACK_NOMEM ? BST_H2_INTERNAL_ERROR : BST_H2_COMPRESSION_ERROR);
		return;
	}
	if (mode == H2_HB_DISCARD) {
		bst_arena_reset(c->scratch);
		return;
	}
	if (s == NULL || s->dead)
		return;
	if (mode == H2_HB_NEW) {
		h2_request_start(c, s, &in, end);
		return;
	}
	/* trailers */
	if (!h2_request_trailers(c, s, &in) || (s->has_cl && s->body_seen != s->cl)) {
		h2c_stream_error(c, sid, BST_H2_PROTOCOL_ERROR);
		return;
	}
	s->remote_closed = true;
	h2_deliver(s);
}

static void on_priority_fields(h2c *c, const bst_h2_frame *f)
{
	/* RFC 9113 section 5.3.1: a stream may not depend on itself. The rest of the RFC 7540 tree is
	 * not used (SETTINGS_NO_RFC7540_PRIORITIES), so nothing else is kept. */
	if (f->has_priority && f->dep == f->stream_id)
		h2c_stream_error(c, f->stream_id, BST_H2_PROTOCOL_ERROR);
}

static void on_headers(h2c *c, const bst_h2_frame *f)
{
	uint32_t sid = f->stream_id;
	bool end = (f->flags & BST_H2_F_END_STREAM) != 0;
	bool done = (f->flags & BST_H2_F_END_HEADERS) != 0;
	if ((sid & 1u) == 0) { /* client streams are odd (RFC 9113 section 5.1.1) */
		h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
		return;
	}
	if (f->data_len == 0 && !done && h2c_charge(c, BST_H2G_EMPTY))
		return;
	h2s *s = h2s_find(c, sid);
	uint8_t mode;
	if (s != NULL) { /* a second header block: the trailers */
		if (s->remote_closed) {
			h2c_stream_error(c, sid, BST_H2_STREAM_CLOSED);
			mode = H2_HB_DISCARD;
		} else if (!end) { /* RFC 9113 section 8.1: a trailer section ends the stream */
			h2c_stream_error(c, sid, BST_H2_PROTOCOL_ERROR);
			mode = H2_HB_DISCARD;
		} else {
			mode = H2_HB_TRAILERS;
		}
	} else if (sid <= c->last_stream) { /* a stream that is over, or an id used out of order */
		h2_closed_how how = h2s_closed_how(c, sid);
		if (how == H2_CL_NONE) {
			h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
			return;
		}
		if (how != H2_CL_LOCAL_RST) {
			h2c_conn_error(c, BST_H2_STREAM_CLOSED);
			return;
		}
		mode = H2_HB_DISCARD; /* racing our own reset: ignored, but decoded */
	} else {
		c->last_stream = sid;
		if (c->goaway_sent || c->graceful_final) { /* the GOAWAY said no more streams */
			mode = H2_HB_DISCARD;
			h2c_stream_error(c, sid, BST_H2_REFUSED_STREAM);
		} else if (c->nstreams >= c->cfg->max_concurrent_streams) {
			mode = H2_HB_DISCARD; /* RFC 9113 section 5.1.2 */
			h2c_stream_error(c, sid, BST_H2_REFUSED_STREAM);
		} else {
			s = h2s_new(c, sid);
			if (s == NULL) {
				mode = H2_HB_DISCARD;
				h2c_stream_error(c, sid, BST_H2_REFUSED_STREAM);
			} else {
				mode = H2_HB_NEW;
				s->remote_closed = false;
			}
		}
		if (c->closed || c->dying)
			return;
	}
	if (c->closed || c->dying)
		return;
	on_priority_fields(c, f);
	c->hb.active = true;
	c->hb.sid = sid;
	c->hb.end_stream = end;
	c->hb.mode = mode;
	c->hb.len = 0;
	c->hb.frames = 0;
	if (!block_append(c, f->data, f->data_len))
		return;
	if (done)
		block_done(c);
}

static void on_continuation(h2c *c, const bst_h2_frame *f)
{
	if (f->stream_id != c->hb.sid) {
		h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
		return;
	}
	bool done = (f->flags & BST_H2_F_END_HEADERS) != 0;
	if (++c->hb.frames > c->cfg->abuse.continuation_max) { /* CVE-2024-27983 and the CONTINUATION flood family */
		bst_h2_guard_hit(BST_H2G_CONTINUATION);
		h2c_conn_error(c, BST_H2_ENHANCE_YOUR_CALM);
		return;
	}
	if (f->data_len == 0 && !done && h2c_charge(c, BST_H2G_EMPTY))
		return;
	if (!block_append(c, f->data, f->data_len))
		return;
	if (done)
		block_done(c);
}

/* ---- DATA ---- */

static void drop_data(h2c *c, h2s *s, const bst_h2_frame *f)
{
	/* The frame counted against the connection window; the bytes go nowhere, so their credit
	 * returns at once. */
	h2_recv_consumed(c, s, f->length);
}

static void on_data(h2c *c, const bst_h2_frame *f)
{
	uint32_t sid = f->stream_id;
	bool end = (f->flags & BST_H2_F_END_STREAM) != 0;
	h2s *s = h2s_find(c, sid);
	bool serr;
	if (s == NULL) {
		if (sid > c->last_stream) { /* DATA on an idle stream */
			h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
			return;
		}
		uint32_t code = h2_recv_account(c, NULL, f->length, &serr);
		if (code != 0) {
			h2c_conn_error(c, code);
			return;
		}
		drop_data(c, NULL, f);
		h2_closed_how how = h2s_closed_how(c, sid);
		if (how == H2_CL_LOCAL_RST || how == H2_CL_NONE)
			return; /* in flight when our reset went out */
		h2c_stream_error(c, sid, BST_H2_STREAM_CLOSED);
		return;
	}
	uint32_t code = h2_recv_account(c, s, f->length, &serr);
	if (code != 0) {
		if (serr) {
			drop_data(c, NULL, f);
			h2c_stream_error(c, sid, code);
		} else {
			h2c_conn_error(c, code);
		}
		return;
	}
	if (s->remote_closed) {
		drop_data(c, NULL, f);
		h2c_stream_error(c, sid, BST_H2_STREAM_CLOSED);
		return;
	}
	if (f->data_len == 0 && !end && h2c_charge(c, BST_H2G_EMPTY))
		return;
	if (f->length > f->data_len) /* padding never reaches a handler: its credit returns now */
		h2_recv_consumed(c, s, f->length - f->data_len);
	s->body_seen += f->data_len;
	if (s->has_cl && (s->body_seen > s->cl || (end && s->body_seen != s->cl))) {
		drop_data(c, NULL, &(bst_h2_frame){ .length = f->data_len });
		h2c_stream_error(c, sid, BST_H2_PROTOCOL_ERROR); /* RFC 9113 section 8.1.1 */
		return;
	}
	const bst_cfg_common *cfg = s->s.cfg;
	if (cfg->client_max_body_size != 0 && s->body_seen > cfg->client_max_body_size &&
	    s->s.req.head.protocol.len == 0) {
		/* A body of unknown length past client_max_body_size: the stream ends (the declared case
		 * was refused with 413 when the head arrived). An extended CONNECT tunnel carries a
		 * byte stream, not a body: its limits are the tunnel's. */
		drop_data(c, NULL, &(bst_h2_frame){ .length = f->data_len });
		h2s_reset(s, BST_H2_CANCEL, BST_STREAM_ERR_CANCEL);
		return;
	}
	if (s->local_closed || s->rejected || s->s.handler == NULL) {
		/* Nobody will read this body (the response is out, or the request was refused): the
		 * bytes are dropped and credited back so the peer is not stalled on them. */
		drop_data(c, s, &(bst_h2_frame){ .length = f->data_len });
		if (end)
			s->remote_closed = true;
		return;
	}
	if (f->data_len > 0) {
		bst_buf *b = bst_buf_new(f->data_len);
		if (b == NULL) {
			h2c_conn_error(c, BST_H2_INTERNAL_ERROR);
			return;
		}
		memcpy(b->data, f->data, f->data_len);
		b->len = f->data_len;
		int rc = bst_chain_add_mem(&s->in, b, 0, f->data_len);
		bst_buf_unref(b);
		if (rc != 0) {
			h2c_conn_error(c, BST_H2_INTERNAL_ERROR);
			return;
		}
	}
	if (end)
		s->remote_closed = true;
	h2_deliver(s);
}

/* ---- the other frames ---- */

static void on_rst(h2c *c, const bst_h2_frame *f)
{
	uint32_t sid = f->stream_id;
	h2s *s = h2s_find(c, sid);
	if (s == NULL && sid > c->last_stream) { /* RST_STREAM on an idle stream */
		h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
		return;
	}
	/* Rapid Reset (CVE-2023-44487): streams opened and cancelled in a tight loop cost the server
	 * their setup and teardown while the client never waits. */
	if (h2c_charge(c, BST_H2G_RST))
		return;
	if (s != NULL)
		h2s_kill(s, BST_STREAM_ERR_CANCEL, H2_CL_REMOTE_RST);
}

static void on_settings(h2c *c, const bst_h2_frame *f)
{
	if (f->flags & BST_H2_F_ACK) {
		c->settings_acked = true;
		return;
	}
	if (h2c_charge(c, BST_H2G_SETTINGS))
		return;
	size_t pos = 0;
	uint16_t id;
	uint32_t v;
	while (bst_h2_settings_next(f, &pos, &id, &v)) {
		switch (id) {
		case BST_H2_S_HEADER_TABLE_SIZE: {
			uint32_t cap = v < c->cfg->header_table_size ? v : c->cfg->header_table_size;
			bst_hpack_enc_set_max(&c->enc, cap);
			break;
		}
		case BST_H2_S_ENABLE_PUSH:
			if (v > 1) {
				h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
				return;
			}
			break;
		case BST_H2_S_INITIAL_WINDOW_SIZE: {
			if (v > 0x7fffffffu) {
				h2c_conn_error(c, BST_H2_FLOW_CONTROL_ERROR);
				return;
			}
			uint32_t code = h2_set_initial_window(c, (int64_t)v);
			if (code != 0) {
				h2c_conn_error(c, code);
				return;
			}
			break;
		}
		case BST_H2_S_MAX_FRAME_SIZE:
			if (v < 16384u || v > 16777215u) {
				h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
				return;
			}
			c->peer_max_frame = v;
			break;
		default: /* MAX_CONCURRENT_STREAMS (we push nothing), MAX_HEADER_LIST_SIZE, unknown ids */
			break;
		}
	}
	c->got_settings = true;
	if (!h2c_queue_ok(c, bst_h2_write_settings(&c->ctl, NULL, 0, true)))
		return;
	h2c_update_partial(c);
	h2c_arm_flush(c);
}

static void final_goaway(h2c *c)
{
	c->graceful_final = true;
	if (bst_h2_write_goaway(&c->ctl, c->last_stream, BST_H2_NO_ERROR) != 0) {
		h2c_close(c);
		return;
	}
	h2c_arm_idle(c);
	h2c_arm_flush(c);
}

static void on_ping(h2c *c, const bst_h2_frame *f)
{
	if (f->flags & BST_H2_F_ACK) {
		if (c->graceful && !c->graceful_final && memcmp(f->ping, "bstdrain", 8) == 0)
			final_goaway(c);
		return;
	}
	if (h2c_charge(c, BST_H2G_PING))
		return;
	if (!h2c_queue_ok(c, bst_h2_write_ping(&c->ctl, f->ping, true)))
		return;
	h2c_arm_flush(c);
}

static void on_window_update(h2c *c, const bst_h2_frame *f)
{
	uint32_t sid = f->stream_id;
	/* A drip of one-byte windows makes the server cut its DATA into tiny frames (CVE-2019-9517
	 * family): the updates are budgeted, and a stream that never gets enough credit times out. */
	if (h2c_charge(c, BST_H2G_WINDOW_UPDATE))
		return;
	bool serr;
	if (sid == 0) {
		uint32_t code = h2_send_window_update(c, NULL, f->value, &serr);
		if (code != 0)
			h2c_conn_error(c, code);
		return;
	}
	h2s *s = h2s_find(c, sid);
	if (s == NULL) {
		if (sid > c->last_stream)
			h2c_conn_error(c, BST_H2_PROTOCOL_ERROR); /* idle */
		return; /* closed: a WINDOW_UPDATE may still arrive */
	}
	uint32_t code = h2_send_window_update(c, s, f->value, &serr);
	if (code != 0)
		h2c_stream_error(c, sid, code);
}

static void on_priority_update(h2c *c, const bst_h2_frame *f)
{
	if (h2c_charge(c, BST_H2G_PRIORITY))
		return;
	if (f->value == 0) { /* RFC 9218 section 7.1: the prioritized stream id 0 */
		h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
		return;
	}
	h2_priority_update(c, f->value, (const char *)f->data, f->data_len);
}

void h2c_frame(h2c *c, const bst_h2_frame *f)
{
	if (!c->got_settings && f->type != BST_H2_SETTINGS) { /* the preface ends with a SETTINGS frame */
		h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
		return;
	}
	if (c->hb.active && (f->type != BST_H2_CONTINUATION)) { /* RFC 9113 section 6.10 */
		h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
		return;
	}
	switch (f->type) {
	case BST_H2_DATA:
		on_data(c, f);
		break;
	case BST_H2_HEADERS:
		on_headers(c, f);
		break;
	case BST_H2_PRIORITY:
		if (h2c_charge(c, BST_H2G_PRIORITY))
			return;
		on_priority_fields(c, f);
		break;
	case BST_H2_RST_STREAM:
		on_rst(c, f);
		break;
	case BST_H2_SETTINGS:
		on_settings(c, f);
		break;
	case BST_H2_PING:
		on_ping(c, f);
		break;
	case BST_H2_GOAWAY:
		c->peer_goaway = true;
		break;
	case BST_H2_WINDOW_UPDATE:
		on_window_update(c, f);
		break;
	case BST_H2_CONTINUATION:
		if (!c->hb.active) { /* a CONTINUATION nobody asked for */
			h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
			return;
		}
		on_continuation(c, f);
		break;
	case BST_H2_PRIORITY_UPDATE:
		on_priority_update(c, f);
		break;
	default: /* RFC 9113 section 4.1: unknown frame types are ignored */
		break;
	}
}

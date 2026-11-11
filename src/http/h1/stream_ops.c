/* The bst_stream_ops of HTTP/1.1: what a handler's send_head, send_body and read_body do to the
 * connection (conn.c reads and parses; this writes the response). */
#include "http/h1/conn_priv.h"

#include <string.h>

#define H1S(bs) ((h1s *)(bs))
#define LIVE(s) (!(s)->c->closed && (!(s)->detached || (s)->own))

static bool add_lit(bst_chain *ch, const char *p, size_t n)
{
	bst_buf *b = bst_buf_new(n);
	if (b == NULL)
		return false;
	memcpy(b->data, p, n);
	b->len = n;
	int rc = bst_chain_add_mem(ch, b, 0, n);
	bst_buf_unref(b);
	return rc == 0;
}

static bool add_buf(bst_chain *ch, bst_buf *b)
{
	int rc = bst_chain_add_mem(ch, b, 0, b->len);
	bst_buf_unref(b);
	return rc == 0;
}

static int h1_send_head(bst_stream *bs, const bst_resp_head *hin, bool end)
{
	h1s *s = H1S(bs);
	h1c *c = s->c;
	if (!LIVE(s) || s->head_sent || s->resp_done || hin->status < 200 || hin->status > 599)
		return -1;
	h1c_enter(c);
	bst_resp_head h = *hin;
	int st = h.status;
	uint8_t minor = s->s.req.head.version_minor;
	bst_h1_head_opts o = { .server_tokens = s->s.cfg->http.server_tokens };
	s->no_body = s->is_head || st == 204 || st == 304;
	if (st == 204 || st == 304) {
		o.omit_length = true;
	} else if (h.content_length >= 0) {
		s->cl_left = h.content_length;
	} else if (s->is_head) {
		o.omit_length = true;
	} else if (end) {
		h.content_length = 0;
	} else if (minor >= 1) {
		o.chunked = true;
		s->chunked = true;
	} else {
		s->close_after = true; /* HTTP/1.0 and no length: the end of the connection is the end */
	}
	if (s->s.req.framing.kind != BST_FRAMING_NONE && !s->body_done)
		h1c_force_discard(c, s); /* an unread request body: the framing of what follows is lost */
	if (h.close)
		s->close_after = true;
	o.close = s->close_after;
	o.keepalive = minor == 0 && !o.close;
	bst_buf *hb = bst_h1_serialize_head(&h, &o);
	int rc = -1;
	if (hb != NULL && add_buf(&s->pre, hb)) {
		s->head_sent = s->head_ready = true;
		rc = 0;
		if (end) {
			s->resp_done = true;
			h1c_pump(c);
		} else {
			h1c_arm_flush(c);
		}
	} else {
		h1c_close(c);
	}
	h1c_leave(c);
	return rc;
}

static int h1_send_interim(bst_stream *bs, int status, const bst_headers *hdrs)
{
	h1s *s = H1S(bs);
	h1c *c = s->c;
	if (!LIVE(s) || s->head_sent || s->s.req.head.version_minor < 1)
		return -1;
	bst_buf *b = bst_h1_serialize_interim(status, hdrs);
	if (b == NULL || !add_buf(&s->pre, b))
		return -1;
	h1c_enter(c);
	s->pre_flush = true;
	h1c_pump(c);
	h1c_leave(c);
	return 0;
}

static int h1_send_body(bst_stream *bs, bst_chain *data, bool end, bst_done_cb cb, void *ud)
{
	h1s *s = H1S(bs);
	h1c *c = s->c;
	if (!LIVE(s) || !s->head_sent || s->resp_done || s->cb != NULL)
		return -1;
	uint64_t len = bst_chain_len(data);
	bool ok = true;
	if (s->no_body) {
		bst_chain_clear(data);
	} else if (s->cl_left >= 0 && len > (uint64_t)s->cl_left) {
		ok = false; /* more than the Content-Length said */
	} else {
		if (s->cl_left >= 0)
			s->cl_left -= (int64_t)len;
		if (s->chunked && len > 0) {
			char pfx[24];
			size_t pn = bst_h1_chunk_prefix(pfx, (size_t)len);
			ok = add_lit(&s->out, pfx, pn);
		}
		if (ok)
			ok = bst_chain_move(&s->out, data) == 0;
		if (ok && s->chunked && len > 0)
			ok = add_lit(&s->out, "\r\n", 2);
		if (ok && s->chunked && end)
			ok = add_lit(&s->out, "0\r\n\r\n", 5);
	}
	if (!ok) {
		h1c_enter(c);
		h1c_close(c);
		h1c_leave(c);
		return -1;
	}
	if (end)
		s->resp_done = true;
	s->cb = cb;
	s->cb_ud = ud;
	h1c_enter(c);
	h1c_pump(c);
	h1c_leave(c);
	return 0;
}

static int h1_send_trailers(bst_stream *bs, const bst_headers *t)
{
	(void)bs;
	(void)t;
	return -1; /* no response trailers yet: nothing in Phase 4 produces them */
}

static void h1_read_body(bst_stream *bs, size_t credit)
{
	h1s *s = H1S(bs);
	h1c *c = s->c;
	if (!LIVE(s))
		return;
	h1c_enter(c);
	s->reading = true;
	s->credit = credit > UINT64_MAX - s->credit ? UINT64_MAX : s->credit + credit;
	if (s->s.req.expect_continue && !s->expect_sent && !s->head_sent && !s->body_done &&
	    s->s.req.head.version_minor >= 1) {
		s->expect_sent = true;
		(void)h1_send_interim(bs, 100, NULL);
	}
	h1c_deliver(s);
	h1c_update_recv(c);
	h1c_leave(c);
}

static void h1_reset(bst_stream *bs, bst_stream_err why)
{
	(void)why;
	h1s *s = H1S(bs);
	if (!LIVE(s))
		return;
	h1c *c = s->c; /* closing the connection frees the stream: keep what is needed after */
	h1c_enter(c);
	h1c_close(c); /* one stream is the whole connection in HTTP/1.1 */
	h1c_leave(c);
}

const bst_stream_ops bst_h1_ops = {
	.send_head = h1_send_head,
	.send_interim = h1_send_interim,
	.send_body = h1_send_body,
	.send_trailers = h1_send_trailers,
	.read_body = h1_read_body,
	.reset = h1_reset,
};


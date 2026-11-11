#include "http/h2/frame.h"

#include <stdlib.h>
#include <string.h>

static uint32_t be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static ssize_t fail(bst_h2_err *e, uint32_t code, uint32_t stream)
{
	e->code = code;
	e->stream = stream;
	return -1;
}

ssize_t bst_h2_frame_parse(const uint8_t *buf, size_t n, uint32_t max_frame, bst_h2_frame *out,
			   bst_h2_err *err)
{
	if (n < BST_H2_FRAME_HDR)
		return 0;
	uint32_t len = (uint32_t)buf[0] << 16 | (uint32_t)buf[1] << 8 | buf[2];
	if (len > max_frame) /* before the payload is read: a huge frame never gets buffered */
		return fail(err, BST_H2_FRAME_SIZE_ERROR, 0);
	if (n - BST_H2_FRAME_HDR < len)
		return 0;
	memset(out, 0, sizeof *out);
	out->type = buf[3];
	out->flags = buf[4];
	out->stream_id = be32(buf + 5) & 0x7fffffffu; /* the reserved bit is ignored and cleared */
	out->length = len;
	const uint8_t *p = buf + BST_H2_FRAME_HDR;
	uint32_t sid = out->stream_id;
	ssize_t used = (ssize_t)(BST_H2_FRAME_HDR + len);

	switch (out->type) {
	case BST_H2_DATA:
	case BST_H2_HEADERS: {
		if (sid == 0)
			return fail(err, BST_H2_PROTOCOL_ERROR, 0);
		bool padded = (out->flags & BST_H2_F_PADDED) != 0;
		bool prio = out->type == BST_H2_HEADERS && (out->flags & BST_H2_F_PRIORITY) != 0;
		uint32_t need = (padded ? 1u : 0u) + (prio ? 5u : 0u);
		if (len < need)
			return fail(err, BST_H2_FRAME_SIZE_ERROR, 0);
		uint32_t pad = padded ? p[0] : 0;
		if (pad > len - need) /* padding as long as the payload or longer (RFC 9113 section 6.1) */
			return fail(err, BST_H2_PROTOCOL_ERROR, 0);
		const uint8_t *q = p + (padded ? 1 : 0);
		if (prio) {
			out->has_priority = true;
			out->exclusive = (q[0] & 0x80) != 0;
			out->dep = be32(q) & 0x7fffffffu;
			out->weight = q[4];
			q += 5;
		}
		out->data = q;
		out->data_len = len - need - pad;
		return used;
	}
	case BST_H2_PRIORITY:
		if (sid == 0)
			return fail(err, BST_H2_PROTOCOL_ERROR, 0);
		if (len != 5) /* a stream error (RFC 9113 section 6.3) */
			return fail(err, BST_H2_FRAME_SIZE_ERROR, sid);
		out->has_priority = true;
		out->exclusive = (p[0] & 0x80) != 0;
		out->dep = be32(p) & 0x7fffffffu;
		out->weight = p[4];
		return used;
	case BST_H2_RST_STREAM:
		if (sid == 0)
			return fail(err, BST_H2_PROTOCOL_ERROR, 0);
		if (len != 4)
			return fail(err, BST_H2_FRAME_SIZE_ERROR, 0);
		out->value = be32(p);
		return used;
	case BST_H2_SETTINGS:
		if (sid != 0)
			return fail(err, BST_H2_PROTOCOL_ERROR, 0);
		if (len % 6 != 0 || ((out->flags & BST_H2_F_ACK) && len != 0))
			return fail(err, BST_H2_FRAME_SIZE_ERROR, 0);
		out->data = p;
		out->data_len = len;
		return used;
	case BST_H2_PUSH_PROMISE: /* only a server sends them; one that arrives here is a violation */
		return fail(err, BST_H2_PROTOCOL_ERROR, 0);
	case BST_H2_PING:
		if (sid != 0)
			return fail(err, BST_H2_PROTOCOL_ERROR, 0);
		if (len != 8)
			return fail(err, BST_H2_FRAME_SIZE_ERROR, 0);
		memcpy(out->ping, p, 8);
		return used;
	case BST_H2_GOAWAY:
		if (sid != 0)
			return fail(err, BST_H2_PROTOCOL_ERROR, 0);
		if (len < 8)
			return fail(err, BST_H2_FRAME_SIZE_ERROR, 0);
		out->last_stream = be32(p) & 0x7fffffffu;
		out->value = be32(p + 4);
		out->data = p + 8;
		out->data_len = len - 8;
		return used;
	case BST_H2_WINDOW_UPDATE:
		if (len != 4)
			return fail(err, BST_H2_FRAME_SIZE_ERROR, 0);
		out->value = be32(p) & 0x7fffffffu;
		return used;
	case BST_H2_CONTINUATION:
		if (sid == 0)
			return fail(err, BST_H2_PROTOCOL_ERROR, 0);
		out->data = p;
		out->data_len = len;
		return used;
	case BST_H2_PRIORITY_UPDATE:
		if (sid != 0)
			return fail(err, BST_H2_PROTOCOL_ERROR, 0);
		if (len < 4)
			return fail(err, BST_H2_FRAME_SIZE_ERROR, 0);
		out->value = be32(p) & 0x7fffffffu;
		out->data = p + 4;
		out->data_len = len - 4;
		return used;
	default: /* unknown types are ignored by the caller (RFC 9113 section 4.1) */
		out->data = p;
		out->data_len = len;
		return used;
	}
}

bool bst_h2_settings_next(const bst_h2_frame *f, size_t *pos, uint16_t *id, uint32_t *val)
{
	if (f->type != BST_H2_SETTINGS || *pos + 6 > f->data_len)
		return false;
	const uint8_t *p = f->data + *pos;
	*id = (uint16_t)((uint16_t)p[0] << 8 | p[1]);
	*val = be32(p + 2);
	*pos += 6;
	return true;
}

/* ---- writers ---- */

void bst_h2_wr_free(bst_h2_wr *w)
{
	free(w->p);
	w->p = NULL;
	w->len = w->cap = 0;
}

int bst_h2_wr_reserve(bst_h2_wr *w, size_t n)
{
	if (n > SIZE_MAX - w->len)
		return -1;
	if (w->len + n <= w->cap)
		return 0;
	size_t cap = w->cap ? w->cap : 256;
	while (cap < w->len + n) {
		if (cap > SIZE_MAX / 2)
			return -1;
		cap *= 2;
	}
	uint8_t *np = realloc(w->p, cap);
	if (np == NULL)
		return -1;
	w->p = np;
	w->cap = cap;
	return 0;
}

void bst_h2_put_head(uint8_t out[BST_H2_FRAME_HDR], uint32_t len, uint8_t type, uint8_t flags,
		     uint32_t stream)
{
	out[0] = (uint8_t)(len >> 16);
	out[1] = (uint8_t)(len >> 8);
	out[2] = (uint8_t)len;
	out[3] = type;
	out[4] = flags;
	put32(out + 5, stream & 0x7fffffffu);
}

static int put_frame(bst_h2_wr *w, uint8_t type, uint8_t flags, uint32_t stream, const uint8_t *pl,
		     size_t n)
{
	if (bst_h2_wr_reserve(w, BST_H2_FRAME_HDR + n) != 0)
		return -1;
	bst_h2_put_head(w->p + w->len, (uint32_t)n, type, flags, stream);
	if (n > 0)
		memcpy(w->p + w->len + BST_H2_FRAME_HDR, pl, n);
	w->len += BST_H2_FRAME_HDR + n;
	return 0;
}

int bst_h2_write_headers(bst_h2_wr *w, uint32_t stream, const uint8_t *block, size_t n,
			 bool end_stream, uint32_t max_frame)
{
	if (max_frame == 0)
		return -1;
	size_t first = n < max_frame ? n : max_frame;
	uint8_t fl = (uint8_t)((end_stream ? BST_H2_F_END_STREAM : 0) | (first == n ? BST_H2_F_END_HEADERS : 0));
	if (put_frame(w, BST_H2_HEADERS, fl, stream, block, first) != 0)
		return -1;
	for (size_t off = first; off < n;) {
		size_t k = n - off < max_frame ? n - off : max_frame;
		if (put_frame(w, BST_H2_CONTINUATION, off + k == n ? BST_H2_F_END_HEADERS : 0, stream,
			      block + off, k) != 0)
			return -1;
		off += k;
	}
	return 0;
}

int bst_h2_write_data(bst_h2_wr *w, uint32_t stream, uint32_t n, bool end_stream)
{
	if (bst_h2_wr_reserve(w, BST_H2_FRAME_HDR) != 0)
		return -1;
	bst_h2_put_head(w->p + w->len, n, BST_H2_DATA, end_stream ? BST_H2_F_END_STREAM : 0, stream);
	w->len += BST_H2_FRAME_HDR;
	return 0;
}

int bst_h2_write_settings(bst_h2_wr *w, const uint32_t (*entries)[2], size_t nentries, bool ack)
{
	if (nentries > 64)
		return -1;
	uint8_t pl[64 * 6];
	for (size_t i = 0; i < nentries; i++) {
		pl[i * 6] = (uint8_t)(entries[i][0] >> 8);
		pl[i * 6 + 1] = (uint8_t)entries[i][0];
		put32(pl + i * 6 + 2, entries[i][1]);
	}
	return put_frame(w, BST_H2_SETTINGS, ack ? BST_H2_F_ACK : 0, 0, pl, ack ? 0 : nentries * 6);
}

int bst_h2_write_ping(bst_h2_wr *w, const uint8_t data[8], bool ack)
{
	return put_frame(w, BST_H2_PING, ack ? BST_H2_F_ACK : 0, 0, data, 8);
}

int bst_h2_write_goaway(bst_h2_wr *w, uint32_t last_stream, uint32_t code)
{
	uint8_t pl[8];
	put32(pl, last_stream & 0x7fffffffu);
	put32(pl + 4, code);
	return put_frame(w, BST_H2_GOAWAY, 0, 0, pl, 8);
}

int bst_h2_write_rst(bst_h2_wr *w, uint32_t stream, uint32_t code)
{
	uint8_t pl[4];
	put32(pl, code);
	return put_frame(w, BST_H2_RST_STREAM, 0, stream, pl, 4);
}

int bst_h2_write_window_update(bst_h2_wr *w, uint32_t stream, uint32_t increment)
{
	uint8_t pl[4];
	put32(pl, increment & 0x7fffffffu);
	return put_frame(w, BST_H2_WINDOW_UPDATE, 0, stream, pl, 4);
}

int bst_h2_write_priority_update(bst_h2_wr *w, uint32_t prioritized, const char *field, size_t n)
{
	if (n > BST_H2_MIN_FRAME - 4)
		return -1;
	uint8_t pl[BST_H2_MIN_FRAME];
	put32(pl, prioritized & 0x7fffffffu);
	if (n > 0)
		memcpy(pl + 4, field, n);
	return put_frame(w, BST_H2_PRIORITY_UPDATE, 0, 0, pl, n + 4);
}

/* HTTP/2 frame codec: every writer round-trips through the parser, and the parser refuses what
 * RFC 9113 section 4 and 6 say to refuse. */
#include "http/h2/frame.h"
#include "tap.h"

#include <string.h>

#define MAXF BST_H2_MIN_FRAME

static ssize_t parse(const bst_h2_wr *w, bst_h2_frame *f, bst_h2_err *e)
{
	return bst_h2_frame_parse(w->p, w->len, MAXF, f, e);
}

/* A frame built by hand: len bytes of payload (zero filled unless pl is given). */
static ssize_t raw(uint32_t len, uint8_t type, uint8_t flags, uint32_t sid, const uint8_t *pl,
		   bst_h2_frame *f, bst_h2_err *e)
{
	static uint8_t b[BST_H2_FRAME_HDR + 1024];
	memset(b, 0, sizeof b);
	bst_h2_put_head(b, len, type, flags, sid);
	if (pl != NULL)
		memcpy(b + BST_H2_FRAME_HDR, pl, len);
	return bst_h2_frame_parse(b, BST_H2_FRAME_HDR + len, MAXF, f, e);
}

TEST(all_frames_roundtrip)
{
	bst_h2_frame f;
	bst_h2_err e;
	bst_h2_wr w = { 0 };

	const uint8_t blk[] = "\x82\x84\x86";
	ASSERT_EQ(bst_h2_write_headers(&w, 5, blk, 3, true, MAXF), 0);
	ASSERT_EQ(parse(&w, &f, &e), (ssize_t)w.len);
	ASSERT_EQ(f.type, BST_H2_HEADERS);
	ASSERT_EQ(f.stream_id, 5);
	ASSERT(f.flags & BST_H2_F_END_STREAM);
	ASSERT(f.flags & BST_H2_F_END_HEADERS);
	ASSERT_EQ(f.data_len, 3);
	ASSERT(memcmp(f.data, blk, 3) == 0);

	w.len = 0;
	ASSERT_EQ(bst_h2_write_data(&w, 7, 100, false), 0);
	ASSERT_EQ(w.len, BST_H2_FRAME_HDR);
	ASSERT_EQ(bst_h2_wr_reserve(&w, 100), 0);
	memset(w.p + w.len, 'x', 100);
	w.len += 100;
	ASSERT_EQ(parse(&w, &f, &e), 109);
	ASSERT_EQ(f.type, BST_H2_DATA);
	ASSERT_EQ(f.stream_id, 7);
	ASSERT_EQ(f.data_len, 100);

	w.len = 0;
	const uint32_t ents[2][2] = { { BST_H2_S_MAX_CONCURRENT_STREAMS, 100 },
				      { BST_H2_S_INITIAL_WINDOW_SIZE, 65535 } };
	ASSERT_EQ(bst_h2_write_settings(&w, ents, 2, false), 0);
	ASSERT_EQ(parse(&w, &f, &e), 21);
	size_t pos = 0;
	uint16_t id;
	uint32_t v;
	ASSERT(bst_h2_settings_next(&f, &pos, &id, &v));
	ASSERT_EQ(id, BST_H2_S_MAX_CONCURRENT_STREAMS);
	ASSERT_EQ(v, 100);
	ASSERT(bst_h2_settings_next(&f, &pos, &id, &v));
	ASSERT_EQ(v, 65535);
	ASSERT(!bst_h2_settings_next(&f, &pos, &id, &v));

	w.len = 0;
	ASSERT_EQ(bst_h2_write_settings(&w, NULL, 0, true), 0);
	ASSERT_EQ(parse(&w, &f, &e), 9);
	ASSERT(f.flags & BST_H2_F_ACK);

	w.len = 0;
	const uint8_t pd[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	ASSERT_EQ(bst_h2_write_ping(&w, pd, true), 0);
	ASSERT_EQ(parse(&w, &f, &e), 17);
	ASSERT(memcmp(f.ping, pd, 8) == 0);
	ASSERT(f.flags & BST_H2_F_ACK);

	w.len = 0;
	ASSERT_EQ(bst_h2_write_goaway(&w, 99, BST_H2_ENHANCE_YOUR_CALM), 0);
	ASSERT_EQ(parse(&w, &f, &e), 17);
	ASSERT_EQ(f.last_stream, 99);
	ASSERT_EQ(f.value, BST_H2_ENHANCE_YOUR_CALM);

	w.len = 0;
	ASSERT_EQ(bst_h2_write_rst(&w, 3, BST_H2_CANCEL), 0);
	ASSERT_EQ(parse(&w, &f, &e), 13);
	ASSERT_EQ(f.type, BST_H2_RST_STREAM);
	ASSERT_EQ(f.value, BST_H2_CANCEL);

	w.len = 0;
	ASSERT_EQ(bst_h2_write_window_update(&w, 0, 12345), 0);
	ASSERT_EQ(parse(&w, &f, &e), 13);
	ASSERT_EQ(f.value, 12345);

	w.len = 0;
	ASSERT_EQ(bst_h2_write_priority_update(&w, 9, "u=1, i", 6), 0);
	ASSERT_EQ(parse(&w, &f, &e), 19);
	ASSERT_EQ(f.type, BST_H2_PRIORITY_UPDATE);
	ASSERT_EQ(f.value, 9);
	ASSERT_EQ(f.data_len, 6);
	ASSERT(memcmp(f.data, "u=1, i", 6) == 0);
	bst_h2_wr_free(&w);
}

TEST(headers_split_into_continuation)
{
	bst_h2_wr w = { 0 };
	uint8_t blk[40000];
	memset(blk, 0x82, sizeof blk);
	ASSERT_EQ(bst_h2_write_headers(&w, 1, blk, sizeof blk, false, MAXF), 0);
	bst_h2_frame f;
	bst_h2_err e;
	size_t off = 0, total = 0;
	int frames = 0;
	while (off < w.len) {
		ssize_t n = bst_h2_frame_parse(w.p + off, w.len - off, MAXF, &f, &e);
		ASSERT(n > 0);
		ASSERT_EQ(f.type, frames == 0 ? BST_H2_HEADERS : BST_H2_CONTINUATION);
		ASSERT_EQ(!!(f.flags & BST_H2_F_END_HEADERS), off + (size_t)n == w.len);
		total += f.data_len;
		off += (size_t)n;
		frames++;
	}
	ASSERT_EQ(frames, 3);
	ASSERT_EQ(total, sizeof blk);
	bst_h2_wr_free(&w);
}

TEST(partial_input_needs_more)
{
	bst_h2_wr w = { 0 };
	bst_h2_frame f;
	bst_h2_err e;
	ASSERT_EQ(bst_h2_write_rst(&w, 3, 8), 0);
	for (size_t i = 0; i < w.len; i++)
		ASSERT_EQ(bst_h2_frame_parse(w.p, i, MAXF, &f, &e), 0);
	bst_h2_wr_free(&w);
}

TEST(size_rules)
{
	bst_h2_frame f;
	bst_h2_err e;
	ASSERT_EQ(raw(7, BST_H2_PING, 0, 0, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_FRAME_SIZE_ERROR);
	ASSERT_EQ(e.stream, 0);
	ASSERT_EQ(raw(5, BST_H2_SETTINGS, 0, 0, NULL, &f, &e), -1); /* not a multiple of 6 */
	ASSERT_EQ(e.code, BST_H2_FRAME_SIZE_ERROR);
	ASSERT_EQ(raw(6, BST_H2_SETTINGS, BST_H2_F_ACK, 0, NULL, &f, &e), -1); /* ACK with a body */
	ASSERT_EQ(e.code, BST_H2_FRAME_SIZE_ERROR);
	ASSERT_EQ(raw(3, BST_H2_RST_STREAM, 0, 1, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_FRAME_SIZE_ERROR);
	ASSERT_EQ(raw(5, BST_H2_WINDOW_UPDATE, 0, 1, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_FRAME_SIZE_ERROR);
	ASSERT_EQ(raw(7, BST_H2_GOAWAY, 0, 0, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_FRAME_SIZE_ERROR);
	/* PRIORITY of the wrong size is a stream error (RFC 9113 section 6.3) */
	ASSERT_EQ(raw(4, BST_H2_PRIORITY, 0, 3, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_FRAME_SIZE_ERROR);
	ASSERT_EQ(e.stream, 3);
	ASSERT_EQ(raw(5, BST_H2_PRIORITY, 0, 3, NULL, &f, &e), 14);
}

TEST(stream_rules)
{
	bst_h2_frame f;
	bst_h2_err e;
	ASSERT_EQ(raw(0, BST_H2_SETTINGS, 0, 1, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_PROTOCOL_ERROR);
	ASSERT_EQ(raw(0, BST_H2_DATA, 0, 0, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_PROTOCOL_ERROR);
	ASSERT_EQ(raw(5, BST_H2_HEADERS, 0, 0, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_PROTOCOL_ERROR);
	ASSERT_EQ(raw(8, BST_H2_PING, 0, 5, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_PROTOCOL_ERROR);
	ASSERT_EQ(raw(4, BST_H2_RST_STREAM, 0, 0, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_PROTOCOL_ERROR);
	ASSERT_EQ(raw(0, BST_H2_CONTINUATION, 0, 0, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_PROTOCOL_ERROR);
	ASSERT_EQ(raw(8, BST_H2_GOAWAY, 0, 1, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_PROTOCOL_ERROR);
	ASSERT_EQ(raw(4, BST_H2_PRIORITY_UPDATE, 0, 1, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_PROTOCOL_ERROR);
	ASSERT_EQ(raw(4, BST_H2_PUSH_PROMISE, 0, 1, NULL, &f, &e), -1); /* a client never pushes */
	ASSERT_EQ(e.code, BST_H2_PROTOCOL_ERROR);
}

TEST(padding_too_long)
{
	bst_h2_frame f;
	bst_h2_err e;
	uint8_t pl[8] = { 8, 'a', 'b', 'c', 'd', 'e', 'f', 'g' }; /* pad 8 in a payload of 8 */
	ASSERT_EQ(raw(8, BST_H2_DATA, BST_H2_F_PADDED, 1, pl, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_PROTOCOL_ERROR);
	pl[0] = 7; /* exactly the rest of the payload: legal, no data */
	ASSERT_EQ(raw(8, BST_H2_DATA, BST_H2_F_PADDED, 1, pl, &f, &e), 17);
	ASSERT_EQ(f.data_len, 0);
	ASSERT_EQ(f.length, 8);
	pl[0] = 3;
	ASSERT_EQ(raw(8, BST_H2_DATA, BST_H2_F_PADDED, 1, pl, &f, &e), 17);
	ASSERT_EQ(f.data_len, 4);
	ASSERT(memcmp(f.data, "abcd", 4) == 0);
	/* HEADERS: padding is checked against what the priority fields leave */
	uint8_t hp[8] = { 3, 0, 0, 0, 0, 16, 0x82, 0 };
	ASSERT_EQ(raw(8, BST_H2_HEADERS, BST_H2_F_PADDED | BST_H2_F_PRIORITY, 1, hp, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_PROTOCOL_ERROR);
	hp[0] = 1;
	ASSERT_EQ(raw(8, BST_H2_HEADERS, BST_H2_F_PADDED | BST_H2_F_PRIORITY, 1, hp, &f, &e), 17);
	ASSERT(f.has_priority);
	ASSERT_EQ(f.weight, 16);
	ASSERT_EQ(f.data_len, 1);
	/* PADDED with no room for the pad length byte */
	ASSERT_EQ(raw(0, BST_H2_DATA, BST_H2_F_PADDED, 1, NULL, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_FRAME_SIZE_ERROR);
}

TEST(over_max_frame)
{
	bst_h2_frame f;
	bst_h2_err e;
	uint8_t head[BST_H2_FRAME_HDR];
	bst_h2_put_head(head, MAXF + 1, BST_H2_DATA, 0, 1);
	/* only the 9 bytes are there: refused without waiting for the payload */
	ASSERT_EQ(bst_h2_frame_parse(head, sizeof head, MAXF, &f, &e), -1);
	ASSERT_EQ(e.code, BST_H2_FRAME_SIZE_ERROR);
	ASSERT_EQ(e.stream, 0);
	bst_h2_put_head(head, MAXF, BST_H2_DATA, 0, 1);
	ASSERT_EQ(bst_h2_frame_parse(head, sizeof head, MAXF, &f, &e), 0);
}

TEST(unknown_type_ignored)
{
	bst_h2_frame f;
	bst_h2_err e;
	uint8_t pl[3] = { 1, 2, 3 };
	ASSERT_EQ(raw(3, 0xfa, 0xff, 0, pl, &f, &e), 12);
	ASSERT_EQ(f.type, 0xfa);
	ASSERT_EQ(f.data_len, 3);
	ASSERT_EQ(raw(3, 0x0b, 0, 7, pl, &f, &e), 12);
}

TEST(reserved_bit_ignored)
{
	bst_h2_frame f;
	bst_h2_err e;
	uint8_t b[13];
	bst_h2_put_head(b, 4, BST_H2_WINDOW_UPDATE, 0, 5);
	b[5] |= 0x80; /* reserved bit of the stream id */
	b[9] = 0x80;  /* reserved bit of the increment */
	b[10] = 0;
	b[11] = 0;
	b[12] = 10;
	ASSERT_EQ(bst_h2_frame_parse(b, sizeof b, MAXF, &f, &e), 13);
	ASSERT_EQ(f.stream_id, 5);
	ASSERT_EQ(f.value, 10);
	/* writers clear it too */
	bst_h2_wr w = { 0 };
	ASSERT_EQ(bst_h2_write_window_update(&w, 0x80000005u, 0x80000001u), 0);
	ASSERT_EQ(w.p[5] & 0x80, 0);
	ASSERT_EQ(w.p[9] & 0x80, 0);
	bst_h2_wr_free(&w);
}

TAP_MAIN()

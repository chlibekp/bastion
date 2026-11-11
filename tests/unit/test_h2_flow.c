/* Flow control (flow.c) and the write scheduler (sched.c) over a socket pair. A client that sets
 * SETTINGS_INITIAL_WINDOW_SIZE to 0 keeps every response body waiting, so the tests decide when
 * the windows open and see in what order the scheduler then writes. */
#include "h2_fixture.h"

#include <stdio.h>
#include <stdlib.h>

static void settings_window(fx *f, uint32_t v)
{
	uint8_t e[6] = { 0, 4, (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
	put_frame(f, BST_H2_SETTINGS, 0, 0, e, 6);
}

static void wu(fx *f, uint32_t sid, uint32_t inc)
{
	uint8_t p[4] = { (uint8_t)(inc >> 24), (uint8_t)(inc >> 16), (uint8_t)(inc >> 8), (uint8_t)inc };
	put_frame(f, BST_H2_WINDOW_UPDATE, 0, sid, p, 4);
}

/* A connection with a client window of 0 and stream 1 open: its response head is out, its body waits. */
static int blocked(fx *f, const char *conf)
{
	if (fx_start(f, conf) != 0)
		return -1;
	put(f, BST_H2_PREFACE, BST_H2_PREFACE_LEN);
	settings_window(f, 0);
	get(f, 1, true);
	collect(f, 50);
	return 0;
}

TEST(window_overflow)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	wu(&f, 0, 0x7fffffffu); /* 65535 + 2^31-1 is past 2^31-1: a connection error (RFC 9113 section 6.9.1) */
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_FLOW_CONTROL_ERROR));
	fx_end(&f);

	ASSERT_EQ(blocked(&f, CONF("")), 0);
	ASSERT_EQ(count(&f, BST_H2_DATA, 1), 0); /* the body waits for the window */
	f.n = 0;
	wu(&f, 1, 0x7fffffffu); /* exactly the largest window is fine ... */
	wu(&f, 1, 1);		/* ... and one more byte is a stream error */
	collect(&f, 50);
	ASSERT(rst_with(&f, 1, BST_H2_FLOW_CONTROL_ERROR));
	fx_end(&f);
}

TEST(zero_increment)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	wu(&f, 0, 0); /* on the connection: a connection error (section 6.9) */
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_PROTOCOL_ERROR));
	fx_end(&f);

	ASSERT_EQ(blocked(&f, CONF("")), 0);
	f.n = 0;
	wu(&f, 1, 0); /* on a stream: a stream error */
	collect(&f, 50);
	ASSERT(rst_with(&f, 1, BST_H2_PROTOCOL_ERROR));
	ASSERT(count(&f, BST_H2_GOAWAY, 0) == 0);
	fx_end(&f);
}

TEST(initial_window_change)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	put(&f, BST_H2_PREFACE, BST_H2_PREFACE_LEN);
	settings_window(&f, 3); /* a window smaller than the 5-byte body */
	get(&f, 1, true);
	collect(&f, 50);
	bst_h2_frame fr;
	ASSERT(find(&f, BST_H2_DATA, 1, &fr) && fr.data_len == 3 && !(fr.flags & BST_H2_F_END_STREAM));
	/* A change applies to streams that exist, and may take the window below zero (section 6.9.2):
	 * 3 bytes went out, so the window is 0 and a new setting of 0 makes it -3. */
	f.n = 0;
	settings_window(&f, 0);
	wu(&f, 1, 4); /* -3 + 4 = 1: one byte may go */
	collect(&f, 50);
	ASSERT_EQ(count(&f, BST_H2_DATA, 1), 1);
	ASSERT(find(&f, BST_H2_DATA, 1, &fr) && fr.data_len == 1 && !(fr.flags & BST_H2_F_END_STREAM));
	f.n = 0;
	wu(&f, 1, 100);
	collect(&f, 50);
	ASSERT(find(&f, BST_H2_DATA, 1, &fr) && fr.data_len == 1 && (fr.flags & BST_H2_F_END_STREAM));
	fx_end(&f);

	/* a window past 2^31-1 is refused */
	ASSERT_EQ(blocked(&f, CONF("")), 0);
	wu(&f, 1, 0x7fffffffu);
	f.n = 0;
	settings_window(&f, 0x7fffffffu);
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_FLOW_CONTROL_ERROR));
	fx_end(&f);
}

TEST(client_exceeds_window)
{
	fx f;
	/* a stream window of 100 bytes: one DATA frame of 101 is more than the client was allowed */
	ASSERT_EQ(fx_start(&f, CONF("http2_initial_window 100;")), 0);
	hello(&f);
	get(&f, 1, false);
	uint8_t body[101];
	memset(body, 'x', sizeof body);
	put_frame(&f, BST_H2_DATA, 0, 1, body, sizeof body);
	collect(&f, 50);
	ASSERT(rst_with(&f, 1, BST_H2_FLOW_CONTROL_ERROR));
	fx_end(&f);

	/* a frame longer than http2_max_frame_size ends the connection before its payload is read */
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	get(&f, 1, false);
	uint8_t head[BST_H2_FRAME_HDR];
	bst_h2_put_head(head, 16385, BST_H2_DATA, 0, 1);
	put(&f, head, sizeof head);
	collect(&f, 50);
	ASSERT(goaway_with(&f, BST_H2_FRAME_SIZE_ERROR));
	fx_end(&f);
}

static void prio_update(fx *f, uint32_t sid, const char *field)
{
	uint8_t pl[64] = { (uint8_t)(sid >> 24), (uint8_t)(sid >> 16), (uint8_t)(sid >> 8), (uint8_t)sid };
	size_t n = strlen(field);
	memcpy(pl + 4, field, n);
	put_frame(f, BST_H2_PRIORITY_UPDATE, 0, 0, pl, 4 + n);
}

TEST(urgency_order)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	put(&f, BST_H2_PREFACE, BST_H2_PREFACE_LEN);
	settings_window(&f, 0);
	get_with(&f, 1, true, "/", "priority", "u=7");
	get_with(&f, 3, true, "/", NULL, NULL); /* the default is 3 */
	get_with(&f, 5, true, "/", "priority", "u=0");
	collect(&f, 50);
	ASSERT_EQ(count(&f, BST_H2_DATA, 0), 0);
	f.n = 0;
	wu(&f, 1, 100);
	wu(&f, 3, 100);
	wu(&f, 5, 100); /* all three open in one read: the scheduler picks the order */
	collect(&f, 50);
	long p1 = position_of(&f, BST_H2_DATA, 1), p3 = position_of(&f, BST_H2_DATA, 3),
	     p5 = position_of(&f, BST_H2_DATA, 5);
	ASSERT(p5 >= 0 && p3 >= 0 && p1 >= 0);
	ASSERT(p5 < p3 && p3 < p1); /* urgency 0 beats 3 beats 7 */
	fx_end(&f);

	/* PRIORITY_UPDATE changes the urgency of a stream that is already waiting */
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	put(&f, BST_H2_PREFACE, BST_H2_PREFACE_LEN);
	settings_window(&f, 0);
	get(&f, 1, true);
	get(&f, 3, true);
	collect(&f, 50);
	f.n = 0;
	prio_update(&f, 3, "u=1");
	wu(&f, 1, 100);
	wu(&f, 3, 100);
	collect(&f, 50);
	ASSERT(position_of(&f, BST_H2_DATA, 3) >= 0 && position_of(&f, BST_H2_DATA, 3) < position_of(&f, BST_H2_DATA, 1));
	fx_end(&f);

	/* with http2_priorities off the Priority header is ignored: first ready, first served */
	ASSERT_EQ(fx_start(&f, CONF("http2_priorities off;")), 0);
	put(&f, BST_H2_PREFACE, BST_H2_PREFACE_LEN);
	settings_window(&f, 0);
	get_with(&f, 1, true, "/", "priority", "u=7");
	get_with(&f, 3, true, "/", "priority", "u=0");
	collect(&f, 50);
	f.n = 0;
	wu(&f, 1, 100);
	wu(&f, 3, 100);
	collect(&f, 50);
	ASSERT(position_of(&f, BST_H2_DATA, 1) >= 0 && position_of(&f, BST_H2_DATA, 1) < position_of(&f, BST_H2_DATA, 3));
	fx_end(&f);
}

/* A configuration whose `return` body is len bytes, so a response is several DATA frames. */
static char *big_conf(size_t len)
{
	const char *pre = "server { listen 8080; location / { return 200 \"";
	const char *post = "\"; } }";
	char *c = malloc(strlen(pre) + len + strlen(post) + 1);
	strcpy(c, pre);
	memset(c + strlen(pre), 'a', len);
	strcpy(c + strlen(pre) + len, post);
	return c;
}

/* The stream ids of the DATA frames, in arrival order. */
static size_t data_order(fx *f, uint32_t *ids, size_t cap)
{
	size_t pos = 0, n = 0;
	bst_h2_frame fr;
	bst_h2_err err;
	ssize_t r;
	while ((r = bst_h2_frame_parse(f->buf + pos, f->n - pos, 1 << 24, &fr, &err)) > 0) {
		pos += (size_t)r;
		if (fr.type == BST_H2_DATA && n < cap)
			ids[n++] = fr.stream_id;
	}
	return n;
}

TEST(incremental_round_robin)
{
	char *conf = big_conf(50000); /* four DATA frames per response at the default frame size */
	fx f;
	ASSERT_EQ(fx_start(&f, conf), 0);
	put(&f, BST_H2_PREFACE, BST_H2_PREFACE_LEN);
	settings_window(&f, 0);
	get_with(&f, 1, true, "/", "priority", "u=3, i");
	get_with(&f, 3, true, "/", "priority", "u=3, i");
	collect(&f, 50);
	f.n = 0;
	wu(&f, 1, 100000);
	wu(&f, 3, 100000);
	wu(&f, 0, 100000);
	collect(&f, 80);
	collect(&f, 80); /* the socket pair holds ~64 KiB: the rest of the body goes out once this end reads */
	uint32_t ids[32];
	size_t n = data_order(&f, ids, 32);
	ASSERT_EQ(n, 8);
	for (size_t i = 1; i < n; i++)
		ASSERT(ids[i] != ids[i - 1]); /* incremental streams of one urgency take turns frame by frame */
	fx_end(&f);

	ASSERT_EQ(fx_start(&f, conf), 0);
	put(&f, BST_H2_PREFACE, BST_H2_PREFACE_LEN);
	settings_window(&f, 0);
	get(&f, 1, true); /* not incremental: served until it is done */
	get(&f, 3, true);
	collect(&f, 50);
	f.n = 0;
	wu(&f, 1, 100000);
	wu(&f, 3, 100000);
	wu(&f, 0, 100000);
	collect(&f, 80);
	collect(&f, 80);
	n = data_order(&f, ids, 32);
	ASSERT_EQ(n, 8);
	for (size_t i = 0; i < 4; i++)
		ASSERT_EQ(ids[i], 1);
	for (size_t i = 4; i < 8; i++)
		ASSERT_EQ(ids[i], 3);
	fx_end(&f);
	free(conf);
}

TEST(connection_window_is_shared)
{
	/* the connection window (the client never raises it past 65535) bounds all streams together */
	char *conf = big_conf(40000);
	fx f;
	ASSERT_EQ(fx_start(&f, conf), 0);
	hello(&f);
	get(&f, 1, true);
	get(&f, 3, true);
	collect(&f, 80);
	size_t total = 0, pos = 0;
	bst_h2_frame fr;
	bst_h2_err err;
	ssize_t r;
	while ((r = bst_h2_frame_parse(f.buf + pos, f.n - pos, 1 << 24, &fr, &err)) > 0) {
		pos += (size_t)r;
		if (fr.type == BST_H2_DATA)
			total += fr.data_len;
	}
	ASSERT_EQ(total, 65535); /* 80000 bytes of bodies, 65535 of window */
	f.n = 0;
	wu(&f, 0, 100000);
	collect(&f, 80);
	pos = total = 0;
	while ((r = bst_h2_frame_parse(f.buf + pos, f.n - pos, 1 << 24, &fr, &err)) > 0) {
		pos += (size_t)r;
		if (fr.type == BST_H2_DATA)
			total += fr.data_len;
	}
	ASSERT_EQ(total, 80000 - 65535);
	fx_end(&f);
	free(conf);
}

TAP_MAIN()

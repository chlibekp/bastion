/* The abuse budgets (guard.c, and their charging in frames.c / conn.c) over a socket pair: every
 * flood of the CVE-2019-9511..9518 / CVE-2023-44487 / CVE-2024-27983 / CVE-2025-8671 families ends
 * in GOAWAY(ENHANCE_YOUR_CALM) and a bastion_h2_abuse_total{kind} count, while a client that
 * behaves like a browser never trips one. */
#include "h2_fixture.h"

#include "core/counters.h"
#include "http/h2/guard.h"

static uint64_t abuse(const char *kind)
{
	char labels[48] = "kind=";
	strcat(labels, kind);
	return bst_counter_get(bst_counter_register("bastion_h2_abuse_total", "", labels));
}

static void open_stream(fx *f, uint32_t sid)
{
	get(f, sid, false); /* the response goes out; the request side stays open */
}

TEST(rapid_reset)
{
	bst_h2_guard_init();
	uint64_t before = abuse("rst");
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("http2_max_concurrent_streams 1000;")), 0);
	hello(&f);
	uint8_t code[4] = { 0, 0, 0, 8 };
	for (uint32_t i = 0; i < 1000; i++) { /* HEADERS then RST_STREAM, as fast as it goes */
		get(&f, 1 + 2 * i, false);
		put_frame(&f, BST_H2_RST_STREAM, 0, 1 + 2 * i, code, 4);
	}
	collect(&f, 100);
	collect(&f, 100);
	ASSERT(goaway_with(&f, BST_H2_ENHANCE_YOUR_CALM));
	ASSERT(count(&f, BST_H2_HEADERS, 0) < 400); /* the handlers' work stopped with the budget */
	ASSERT(abuse("rst") > before);
	fx_end(&f);
}

TEST(made_you_reset)
{
	uint64_t before = abuse("server_reset");
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("http2_max_concurrent_streams 1000;")), 0);
	hello(&f);
	uint8_t zero[4] = { 0, 0, 0, 0 };
	for (uint32_t i = 0; i < 600; i++) { /* resets the server sends because of the client's frames */
		open_stream(&f, 1 + 2 * i);
		put_frame(&f, BST_H2_WINDOW_UPDATE, 0, 1 + 2 * i, zero, 4);
	}
	collect(&f, 100);
	collect(&f, 100);
	ASSERT(goaway_with(&f, BST_H2_ENHANCE_YOUR_CALM));
	ASSERT(abuse("server_reset") > before);
	fx_end(&f);
}

TEST(continuation_flood)
{
	uint64_t before = abuse("continuation");
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("http2_abuse { continuation_max 8; }")), 0);
	hello(&f);
	uint8_t blk[256];
	size_t n = get_block(&f, blk, sizeof blk, "/", NULL, NULL);
	put_frame(&f, BST_H2_HEADERS, BST_H2_F_END_STREAM, 1, blk, n);
	uint8_t filler[16] = { 0 }; /* a literal that never ends: no END_HEADERS in sight */
	for (int i = 0; i < 30; i++)
		put_frame(&f, BST_H2_CONTINUATION, 0, 1, filler, sizeof filler);
	collect(&f, 100);
	ASSERT(goaway_with(&f, BST_H2_ENHANCE_YOUR_CALM));
	ASSERT(abuse("continuation") > before);
	fx_end(&f);
}

TEST(continuation_size_cap)
{
	fx f;
	/* ten 16 KiB frames are fewer than continuation_max but past the header list size x 4 */
	ASSERT_EQ(fx_start(&f, CONF("http2_max_header_list_size 4k;")), 0);
	hello(&f);
	uint8_t blk[256];
	size_t n = get_block(&f, blk, sizeof blk, "/", NULL, NULL);
	put_frame(&f, BST_H2_HEADERS, BST_H2_F_END_STREAM, 1, blk, n);
	static uint8_t big[16384];
	for (int i = 0; i < 10; i++)
		put_frame(&f, BST_H2_CONTINUATION, 0, 1, big, sizeof big);
	collect(&f, 100);
	ASSERT(goaway_with(&f, BST_H2_ENHANCE_YOUR_CALM) || goaway_with(&f, BST_H2_COMPRESSION_ERROR));
	fx_end(&f);
}

TEST(settings_flood)
{
	uint64_t before = abuse("settings");
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	for (int i = 0; i < 300; i++)
		put_frame(&f, BST_H2_SETTINGS, 0, 0, NULL, 0);
	collect(&f, 100);
	ASSERT(goaway_with(&f, BST_H2_ENHANCE_YOUR_CALM));
	ASSERT(abuse("settings") > before);
	fx_end(&f);
}

TEST(ping_flood)
{
	uint64_t before = abuse("ping");
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	uint8_t data[8] = { 0 };
	for (int i = 0; i < 400; i++)
		put_frame(&f, BST_H2_PING, 0, 0, data, 8);
	collect(&f, 100);
	ASSERT(goaway_with(&f, BST_H2_ENHANCE_YOUR_CALM));
	ASSERT(count(&f, BST_H2_PING, 0) < 200); /* the answers stopped with the budget */
	ASSERT(abuse("ping") > before);
	fx_end(&f);
}

TEST(control_queue_bound)
{
	uint64_t before = abuse("control_queue");
	fx f;
	/* the client never reads: answers pile up until the queue limit, then the connection goes */
	ASSERT_EQ(fx_start(&f, CONF("http2_abuse { ping_rate 100000; control_queue_max 4k; }")), 0);
	hello(&f);
	uint8_t data[8] = { 0 };
	for (int i = 0; i < 20000; i++)
		put_frame(&f, BST_H2_PING, 0, 0, data, 8);
	collect(&f, 100);
	ASSERT(abuse("control_queue") > before);
	fx_end(&f);
}

TEST(empty_frames)
{
	uint64_t before = abuse("empty");
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	open_stream(&f, 1);
	for (int i = 0; i < 400; i++)
		put_frame(&f, BST_H2_DATA, 0, 1, NULL, 0); /* no payload, no END_STREAM */
	collect(&f, 100);
	ASSERT(goaway_with(&f, BST_H2_ENHANCE_YOUR_CALM));
	ASSERT(abuse("empty") > before);
	fx_end(&f);
}

TEST(dependency_flood)
{
	uint64_t before = abuse("priority");
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	uint8_t pr[5] = { 0, 0, 0, 3, 10 }; /* RFC 7540 PRIORITY: ignored, but not free */
	for (int i = 0; i < 1000; i++)
		put_frame(&f, BST_H2_PRIORITY, 0, 1, pr, 5);
	collect(&f, 100);
	ASSERT(goaway_with(&f, BST_H2_ENHANCE_YOUR_CALM));
	ASSERT(abuse("priority") > before);
	fx_end(&f);
}

TEST(window_update_flood)
{
	uint64_t before = abuse("window_update");
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("http2_abuse { window_update_rate 100; }")), 0);
	hello(&f);
	uint8_t one[4] = { 0, 0, 0, 1 };
	for (int i = 0; i < 400; i++)
		put_frame(&f, BST_H2_WINDOW_UPDATE, 0, 0, one, 4);
	collect(&f, 100);
	ASSERT(goaway_with(&f, BST_H2_ENHANCE_YOUR_CALM));
	ASSERT(abuse("window_update") > before);
	fx_end(&f);
}

TEST(legitimate_browser_load)
{
	fx f;
	ASSERT_EQ(fx_start(&f, CONF("")), 0);
	hello(&f);
	uint8_t code[4] = { 0, 0, 0, 8 };
	/* a page load: 100 streams, a third cancelled, a few SETTINGS and PINGs, some PRIORITY_UPDATEs */
	for (uint32_t i = 0; i < 100; i++) {
		get(&f, 1 + 2 * i, true);
		if (i % 3 == 0)
			put_frame(&f, BST_H2_RST_STREAM, 0, 1 + 2 * i, code, 4);
	}
	uint8_t data[8] = { 0 };
	for (int i = 0; i < 5; i++) {
		put_frame(&f, BST_H2_PING, 0, 0, data, 8);
		put_frame(&f, BST_H2_SETTINGS, 0, 0, NULL, 0);
	}
	collect(&f, 100);
	ASSERT(count(&f, BST_H2_GOAWAY, 0) == 0);
	ASSERT(count(&f, BST_H2_DATA, 0) >= 60);
	fx_end(&f);
}

TAP_MAIN()

#include "handlers/range.h"
#include "tap.h"

#include <stdint.h>
#include <string.h>

static int parse(const char *h, long long size, bst_range *r, int max, int *n)
{
	return bst_range_parse((bst_str){ h, (uint32_t)strlen(h) }, (off_t)size, r, max, n);
}

TEST(range_forms)
{
	bst_range r[8];
	int n;
	ASSERT_EQ(parse("bytes=0-0", 100, r, 8, &n), BST_RANGE_OK);
	ASSERT(n == 1 && r[0].start == 0 && r[0].end == 0);
	ASSERT_EQ(parse("bytes=-5", 100, r, 8, &n), BST_RANGE_OK);
	ASSERT(n == 1 && r[0].start == 95 && r[0].end == 99);
	ASSERT_EQ(parse("bytes=5-", 100, r, 8, &n), BST_RANGE_OK);
	ASSERT(n == 1 && r[0].start == 5 && r[0].end == 99);
	ASSERT_EQ(parse("bytes=90-5000", 100, r, 8, &n), BST_RANGE_OK); /* past the end: clamped */
	ASSERT(n == 1 && r[0].start == 90 && r[0].end == 99);
	ASSERT_EQ(parse("bytes=-500", 100, r, 8, &n), BST_RANGE_OK); /* longer than the file */
	ASSERT(n == 1 && r[0].start == 0 && r[0].end == 99);
	ASSERT_EQ(parse("BYTES= 1-2 , 10-11", 100, r, 8, &n), BST_RANGE_OK);
	ASSERT(n == 2 && r[1].start == 10);
	ASSERT_EQ(parse("bytes=1-2,,3-4", 100, r, 8, &n), BST_RANGE_OK); /* empty list elements */
	ASSERT(n == 1 && r[0].start == 1 && r[0].end == 4);
}

TEST(range_416)
{
	bst_range r[8];
	int n;
	ASSERT_EQ(parse("bytes=100-", 50, r, 8, &n), BST_RANGE_416);
	ASSERT_EQ(parse("bytes=50-60", 50, r, 8, &n), BST_RANGE_416);
	ASSERT_EQ(parse("bytes=-0", 50, r, 8, &n), BST_RANGE_416);
	ASSERT_EQ(parse("bytes=0-0", 0, r, 8, &n), BST_RANGE_416); /* an empty file has no byte 0 */
	ASSERT_EQ(parse("bytes=100-,200-", 50, r, 8, &n), BST_RANGE_416);
}

TEST(range_malformed_ignored)
{
	bst_range r[8];
	int n;
	const char *bad[] = { "bytes=abc", "bytes=", "bytes=-", "bytes=5-3", "bytes=1-2x", "items=1-2",
			      "bytes 1-2", "", "bytes=1", "bytes=1-2,x", "bytes=--1", "bytes=1--2" };
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
		ASSERT_EQ(parse(bad[i], 100, r, 8, &n), BST_RANGE_NONE);
}

TEST(range_abuse)
{
	static char h[100000];
	static bst_range r[16];
	int n;
	size_t w = (size_t)snprintf(h, sizeof h, "bytes=");
	for (int i = 0; i < 10000 && w + 24 < sizeof h; i++)
		w += (size_t)snprintf(h + w, sizeof h - w, "%d-%d,", i * 3, i * 3 + 1);
	/* 10,000 ranges against a limit of 16: not honoured */
	ASSERT_EQ(parse(h, 1 << 20, r, 16, &n), BST_RANGE_NONE);
	/* the same, but all one overlapping run: still bounded by max specs */
	w = (size_t)snprintf(h, sizeof h, "bytes=");
	for (int i = 0; i < 10000 && w + 16 < sizeof h; i++)
		w += (size_t)snprintf(h + w, sizeof h - w, "0-%d,", 99);
	ASSERT_EQ(parse(h, 100, r, 16, &n), BST_RANGE_NONE);
}

TEST(range_overlap_coalesced)
{
	bst_range r[8];
	int n;
	ASSERT_EQ(parse("bytes=0-10,5-20,21-30,40-50", 100, r, 8, &n), BST_RANGE_OK);
	ASSERT(n == 2 && r[0].start == 0 && r[0].end == 30 && r[1].start == 40 && r[1].end == 50);
	ASSERT_EQ(parse("bytes=40-50,0-10,8-12", 100, r, 8, &n), BST_RANGE_OK); /* sorted too */
	ASSERT(n == 2 && r[0].start == 0 && r[0].end == 12);
	ASSERT_EQ(parse("bytes=0-99,0-99,0-99", 100, r, 8, &n), BST_RANGE_OK);
	ASSERT(n == 1);
}

TEST(range_overflow)
{
	bst_range r[8];
	int n;
	ASSERT_EQ(parse("bytes=9223372036854775807-", 100, r, 8, &n), BST_RANGE_416);
	ASSERT_EQ(parse("bytes=99999999999999999999999999-", 100, r, 8, &n), BST_RANGE_416);
	ASSERT_EQ(parse("bytes=0-99999999999999999999999999", 100, r, 8, &n), BST_RANGE_OK);
	ASSERT(n == 1 && r[0].end == 99);
	ASSERT_EQ(parse("bytes=-99999999999999999999999999", 100, r, 8, &n), BST_RANGE_OK);
	ASSERT(n == 1 && r[0].start == 0);
	ASSERT_EQ(parse("bytes=9223372036854775806-9223372036854775807", INT64_MAX, r, 8, &n),
		  BST_RANGE_OK);
	ASSERT(n == 1 && r[0].start == INT64_MAX - 1 && r[0].end == INT64_MAX - 1);
	ASSERT_EQ(parse("bytes=0-1,9223372036854775806-", INT64_MAX, r, 8, &n), BST_RANGE_OK);
	ASSERT_EQ(n, 2);
}

TEST(if_range_mismatch)
{
	bst_str tag = BST_S("\"abc\"");
	ASSERT(bst_if_range_ok(BST_S("\"abc\""), tag, true, 784111777));
	ASSERT(!bst_if_range_ok(BST_S("\"abd\""), tag, true, 784111777));
	ASSERT(!bst_if_range_ok(BST_S("W/\"abc\""), tag, true, 784111777)); /* weak never */
	ASSERT(!bst_if_range_ok(BST_S("\"abc\""), BST_S("W/\"abc\""), true, 0));
	ASSERT(bst_if_range_ok(BST_S("Sun, 06 Nov 1994 08:49:37 GMT"), tag, true, 784111777));
	ASSERT(!bst_if_range_ok(BST_S("Sun, 06 Nov 1994 08:49:38 GMT"), tag, true, 784111777));
	ASSERT(!bst_if_range_ok(BST_S("garbage"), tag, true, 784111777));
	ASSERT(!bst_if_range_ok(BST_S(""), tag, true, 784111777));
	ASSERT(!bst_if_range_ok(BST_S("Sun, 06 Nov 1994 08:49:37 GMT"), tag, false, 0));
}

TAP_MAIN()

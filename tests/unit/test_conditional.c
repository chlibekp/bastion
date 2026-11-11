#include "http/conditional.h"
#include "tap.h"

#include <string.h>

#define MT 784111777 /* Sun, 06 Nov 1994 08:49:37 GMT */
#define D_EQ "Sun, 06 Nov 1994 08:49:37 GMT"
#define D_BEFORE "Sun, 06 Nov 1994 08:49:36 GMT"

static bst_validators val(void)
{
	return (bst_validators){ true, BST_S("\"v1\""), true, MT };
}

static bst_cond_result run(bst_headers *h, bst_method m)
{
	bst_validators v = val();
	return bst_evaluate_preconditions(h, &v, m);
}

static void add(bst_headers *h, const char *n, const char *v)
{
	if (bst_headers_add(h, (bst_str){ n, (uint32_t)strlen(n) }, (bst_str){ v, (uint32_t)strlen(v) }) != 0)
		abort();
}

/* The reference: RFC 9110 section 13.2.2, written as plainly as possible. */
static bst_cond_result model(bst_method m, int im, int ius, int inm, int ims)
{
	bool gh = m == BST_M_GET || m == BST_M_HEAD;
	if (im) {
		if (im == 2)
			return BST_COND_412;
	} else if (ius == 2) {
		return BST_COND_412;
	}
	if (inm) {
		if (inm == 1)
			return gh ? BST_COND_304 : BST_COND_412;
		return BST_COND_PROCEED;
	}
	if (gh && ims == 1)
		return BST_COND_304;
	return BST_COND_PROCEED;
}

TEST(precedence)
{
	bst_arena *a = bst_arena_new(1 << 14);
	int checked = 0;
	for (int m = 0; m < 2; m++)
		for (int im = 0; im < 3; im++)
			for (int ius = 0; ius < 3; ius++)
				for (int inm = 0; inm < 3; inm++)
					for (int ims = 0; ims < 3; ims++) {
						bst_headers h;
						bst_headers_init(&h, a);
						if (im)
							add(&h, "If-Match", im == 1 ? "\"v1\"" : "\"zz\"");
						if (ius)
							add(&h, "If-Unmodified-Since", ius == 1 ? D_EQ : D_BEFORE);
						if (inm)
							add(&h, "If-None-Match", inm == 1 ? "\"v1\"" : "\"zz\"");
						if (ims)
							add(&h, "If-Modified-Since", ims == 1 ? D_EQ : D_BEFORE);
						bst_method meth = m ? BST_M_POST : BST_M_GET;
						bst_cond_result got = run(&h, meth), want = model(meth, im, ius, inm, ims);
						if (got != want) {
							ASSERT_EQ(got, want); /* names the combination in the failure */
						}
						checked++;
					}
	ASSERT_EQ(checked, 162);
	bst_arena_free(a);
}

TEST(if_none_match_weak)
{
	bst_arena *a = bst_arena_new(1 << 12);
	bst_headers h;
	bst_headers_init(&h, a);
	add(&h, "If-None-Match", "W/\"v1\"");
	ASSERT_EQ(run(&h, BST_M_GET), BST_COND_304); /* weak comparison: W/ is ignored */
	bst_headers_init(&h, a);
	add(&h, "If-None-Match", "\"a\", \"b\" ,\"v1\"");
	ASSERT_EQ(run(&h, BST_M_HEAD), BST_COND_304);
	bst_headers_init(&h, a);
	add(&h, "If-None-Match", "*");
	ASSERT_EQ(run(&h, BST_M_GET), BST_COND_304);
	ASSERT_EQ(run(&h, BST_M_PUT), BST_COND_412);
	bst_headers_init(&h, a);
	add(&h, "If-None-Match", "\"a\"");
	add(&h, "If-None-Match", "\"v1\""); /* several lines are one list */
	ASSERT_EQ(run(&h, BST_M_GET), BST_COND_304);
	bst_headers_init(&h, a);
	add(&h, "If-None-Match", "garbage");
	ASSERT_EQ(run(&h, BST_M_GET), BST_COND_PROCEED);
	bst_arena_free(a);
}

TEST(if_match_strong)
{
	bst_arena *a = bst_arena_new(1 << 12);
	bst_headers h;
	bst_headers_init(&h, a);
	add(&h, "If-Match", "\"v1\"");
	ASSERT_EQ(run(&h, BST_M_PUT), BST_COND_PROCEED);
	bst_headers_init(&h, a);
	add(&h, "If-Match", "W/\"v1\""); /* the client's weak tag never matches strongly */
	ASSERT_EQ(run(&h, BST_M_PUT), BST_COND_412);
	bst_headers_init(&h, a);
	add(&h, "If-Match", "*");
	ASSERT_EQ(run(&h, BST_M_PUT), BST_COND_PROCEED);
	bst_validators weak = { true, BST_S("W/\"v1\""), true, MT }; /* a weak validator of ours */
	bst_headers_init(&h, a);
	add(&h, "If-Match", "\"v1\"");
	ASSERT_EQ(bst_evaluate_preconditions(&h, &weak, BST_M_PUT), BST_COND_412);
	bst_validators none = { false, { NULL, 0 }, true, MT };
	ASSERT_EQ(bst_evaluate_preconditions(&h, &none, BST_M_PUT), BST_COND_412);
	bst_arena_free(a);
}

TEST(invalid_date_ignored)
{
	bst_arena *a = bst_arena_new(1 << 12);
	bst_headers h;
	bst_headers_init(&h, a);
	add(&h, "If-Modified-Since", "yesterday-ish");
	ASSERT_EQ(run(&h, BST_M_GET), BST_COND_PROCEED);
	bst_headers_init(&h, a);
	add(&h, "If-Unmodified-Since", "Sun, 31 Feb 1994 08:49:37 GMT"); /* no such day */
	ASSERT_EQ(run(&h, BST_M_GET), BST_COND_PROCEED);
	bst_headers_init(&h, a);
	add(&h, "If-Modified-Since", D_EQ);
	add(&h, "If-Modified-Since", D_BEFORE); /* repeated: ignored */
	ASSERT_EQ(run(&h, BST_M_GET), BST_COND_PROCEED);
	bst_arena_free(a);
}

TEST(date_formats)
{
	time_t t;
	ASSERT(bst_http_date_parse(BST_S("Sun, 06 Nov 1994 08:49:37 GMT"), &t) && t == MT);
	ASSERT(bst_http_date_parse(BST_S("Sunday, 06-Nov-94 08:49:37 GMT"), &t) && t == MT);
	ASSERT(bst_http_date_parse(BST_S("Sun Nov  6 08:49:37 1994"), &t) && t == MT);
	ASSERT(bst_http_date_parse(BST_S("  Sun, 06 Nov 1994 08:49:37 GMT "), &t) && t == MT);
	ASSERT(!bst_http_date_parse(BST_S("Sun, 06 Nov 1994 08:49:37 PST"), &t));
	ASSERT(!bst_http_date_parse(BST_S("Sun, 06 Xyz 1994 08:49:37 GMT"), &t));
	ASSERT(!bst_http_date_parse(BST_S("Sun, 06 Nov 1994 25:49:37 GMT"), &t));
	ASSERT(!bst_http_date_parse(BST_S(""), &t));
	ASSERT(bst_http_date_parse(BST_S("Thu, 01 Jan 1970 00:00:00 GMT"), &t) && t == 0);
	ASSERT(bst_http_date_parse(BST_S("Mon, 29 Feb 2016 00:00:00 GMT"), &t) && t == 1456704000);
	ASSERT(!bst_http_date_parse(BST_S("Mon, 29 Feb 2015 00:00:00 GMT"), &t));
}

TEST(etag_format)
{
	char b[BST_ETAG_MAX];
	size_t n = bst_etag_format(0x1234abcd, 255, b, sizeof b);
	ASSERT(n > 0 && strcmp(b, "\"1234abcd-ff\"") == 0);
	ASSERT_EQ(bst_etag_format(1, 2, b, 4), 0); /* too small */
}

TAP_MAIN()

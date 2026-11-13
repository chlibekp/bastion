/* RFC 9111 storage and freshness policy (cache/policy.h), table-driven; section numbers in
 * comments are RFC 9111 unless named otherwise. */
#include "cache/policy.h"
#include "http/cache_control.h"
#include "tap.h"

#include <string.h>

static bst_arena *A;

/* "name: value\n" lines into a header list. */
static void hdrs(bst_headers *h, const char *lines)
{
	if (A == NULL)
		A = bst_arena_new(1 << 16);
	bst_headers_init(h, A);
	const char *p = lines;
	while (p != NULL && *p) {
		const char *nl = strchr(p, '\n');
		size_t len = nl ? (size_t)(nl - p) : strlen(p);
		const char *c = memchr(p, ':', len);
		if (c != NULL) {
			const char *v = c + 1;
			while (*v == ' ')
				v++;
			bst_headers_add(h, (bst_str){ p, (uint32_t)(c - p) },
					(bst_str){ v, (uint32_t)(p + len - v) });
		}
		p = nl ? nl + 1 : NULL;
	}
}

static bst_req_head req(bst_method m, const char *lines)
{
	bst_req_head r;
	memset(&r, 0, sizeof r);
	r.method = m;
	hdrs(&r.headers, lines);
	return r;
}

static const bst_cache_policy_cfg CFG = { .heuristic_max = 86400 };

static bool stores(bst_method m, const char *rq, int st, const char *rs, const bst_cache_policy_cfg *c,
		   const char **why)
{
	bst_req_head r = req(m, rq);
	bst_headers h;
	hdrs(&h, rs);
	return bst_cache_storable(&r, st, &h, c ? c : &CFG, why);
}

TEST(no_store_either_side) /* 3, 5.2.1.5, 5.2.2.5 */
{
	const char *why;
	ASSERT(!stores(BST_M_GET, "", 200, "cache-control: max-age=60, no-store", NULL, &why));
	ASSERT_STR(why, "no-store");
	ASSERT(!stores(BST_M_GET, "cache-control: no-store", 200, "cache-control: max-age=60", NULL, &why));
	ASSERT_STR(why, "request no-store");
	ASSERT(stores(BST_M_GET, "", 200, "cache-control: max-age=60", NULL, &why));
}

TEST(private_not_stored) /* 5.2.2.7 */
{
	const char *why;
	ASSERT(!stores(BST_M_GET, "", 200, "cache-control: private, max-age=60", NULL, &why));
	ASSERT_STR(why, "private");
	ASSERT(!stores(BST_M_GET, "", 200, "cache-control: private=\"x\", max-age=60", NULL, &why));
}

TEST(set_cookie_default_not_stored)
{
	const char *why;
	ASSERT(!stores(BST_M_GET, "", 200, "cache-control: max-age=60\nset-cookie: a=b", NULL, &why));
	ASSERT_STR(why, "set-cookie");
	bst_cache_policy_cfg c = CFG;
	c.cookies = BST_CACHE_COOKIES_STRIP;
	ASSERT(stores(BST_M_GET, "", 200, "cache-control: max-age=60\nset-cookie: a=b", &c, NULL));
}

TEST(authorization_rule) /* 3.5 */
{
	const char *why;
	const char *au = "authorization: Bearer x";
	ASSERT(!stores(BST_M_GET, au, 200, "cache-control: max-age=60", NULL, &why));
	ASSERT_STR(why, "authorization");
	ASSERT(stores(BST_M_GET, au, 200, "cache-control: public, max-age=60", NULL, NULL));
	ASSERT(stores(BST_M_GET, au, 200, "cache-control: s-maxage=60", NULL, NULL));
	ASSERT(stores(BST_M_GET, au, 200, "cache-control: must-revalidate, max-age=60", NULL, NULL));
}

TEST(freshness_order) /* 4.2.1, RFC 9213 2.2 */
{
	bst_cache_valid v[] = { { 200, 77 } };
	bst_cache_policy_cfg c = CFG;
	c.valid = v;
	c.nvalid = 1;
	struct {
		const char *h;
		int64_t life;
		const char *src;
	} t[] = {
		{ "cdn-cache-control: max-age=5\ncache-control: s-maxage=9, max-age=8", 5, "cdn-cache-control" },
		{ "cache-control: s-maxage=9, max-age=8", 9, "s-maxage" },
		{ "cache-control: max-age=8\nexpires: Thu, 01 Jan 2026 00:01:00 GMT\n"
		  "date: Thu, 01 Jan 2026 00:00:00 GMT", 8, "max-age" },
		{ "expires: Thu, 01 Jan 2026 00:01:00 GMT\ndate: Thu, 01 Jan 2026 00:00:00 GMT", 60, "expires" },
		{ "expires: 0\ndate: Thu, 01 Jan 2026 00:00:00 GMT", 0, "expires" },
		{ "", 77, "cache_valid" },
		{ "last-modified: Thu, 01 Jan 2026 00:00:00 GMT\ndate: Sun, 11 Jan 2026 00:00:00 GMT", 86400, "heuristic" },
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
		bst_headers h;
		hdrs(&h, t[i].h);
		bst_freshness f;
		bst_cache_freshness(i == 6 ? 203 : 200, &h, &c, 1767225600, &f);
		ASSERT_EQ(f.lifetime, t[i].life);
		ASSERT_STR(f.source, t[i].src);
	}
	bst_headers h; /* heuristic: 10 % of the time since Last-Modified, capped */
	hdrs(&h, "last-modified: Thu, 01 Jan 2026 00:00:00 GMT\ndate: Thu, 01 Jan 2026 01:40:00 GMT");
	bst_freshness f;
	bst_cache_freshness(200, &h, &CFG, 0, &f);
	ASSERT_EQ(f.lifetime, 600);
}

TEST(age_calc) /* 4.2.3 */
{
	/* request at 100, response at 102, Date 90 (origin clock behind), Age 5, now 110 */
	ASSERT_EQ(bst_cache_age(90, 5, 100, 102, 110), 12 + 8);
	/* clock skew: the origin's Date is ahead of ours: the apparent age is clamped to 0 */
	ASSERT_EQ(bst_cache_age(200, BST_CC_NONE, 100, 101, 101), 1);
	/* no Date, no Age: just the time it has been here plus the delay */
	ASSERT_EQ(bst_cache_age(BST_CC_NONE, BST_CC_NONE, 100, 100, 130), 30);
	bst_headers h;
	hdrs(&h, "date: Thu, 01 Jan 2026 00:00:00 GMT\nage: 7");
	int64_t d, a;
	bst_cache_resp_times(&h, &d, &a);
	ASSERT_EQ(d, 1767225600);
	ASSERT_EQ(a, 7);
}

TEST(no_cache_requires_revalidation) /* 5.2.2.4 */
{
	bst_headers h;
	hdrs(&h, "cache-control: no-cache, max-age=60\netag: \"a\"");
	bst_freshness f;
	bst_cache_freshness(200, &h, &CFG, 0, &f);
	ASSERT(f.no_cache);
	ASSERT(stores(BST_M_GET, "", 200, "cache-control: no-cache\netag: \"a\"", NULL, NULL));
}

TEST(must_revalidate_forbids_stale) /* 5.2.2.2, 5.2.2.8, 5.2.2.10 */
{
	const char *t[] = { "cache-control: max-age=1, must-revalidate",
			    "cache-control: max-age=1, proxy-revalidate", "cache-control: s-maxage=1" };
	for (size_t i = 0; i < 3; i++) {
		bst_headers h;
		hdrs(&h, t[i]);
		bst_freshness f;
		bst_cache_freshness(200, &h, &CFG, 0, &f);
		ASSERT(f.must_revalidate);
	}
}

TEST(immutable) /* RFC 8246 */
{
	bst_headers h;
	hdrs(&h, "cache-control: max-age=31536000, immutable");
	bst_freshness f;
	bst_cache_freshness(200, &h, &CFG, 0, &f);
	ASSERT(f.immutable);
	ASSERT_EQ(f.lifetime, 31536000);
}

TEST(request_no_cache)
{
	bst_headers h;
	hdrs(&h, "cache-control: no-cache");
	ASSERT(!bst_cache_req_revalidate(&h, &CFG)); /* off by default */
	bst_cache_policy_cfg c = CFG;
	c.honor_request_cc = true;
	ASSERT(bst_cache_req_revalidate(&h, &c));
	hdrs(&h, "cache-control: max-age=0");
	ASSERT(bst_cache_req_revalidate(&h, &c));
	hdrs(&h, "pragma: no-cache");
	ASSERT(bst_cache_req_revalidate(&h, &c));
	hdrs(&h, "cache-control: max-age=5");
	ASSERT(!bst_cache_req_revalidate(&h, &c));
}

TEST(vary_star) /* 4.1 */
{
	const char *why;
	ASSERT(!stores(BST_M_GET, "", 200, "cache-control: max-age=60\nvary: accept, *", NULL, &why));
	ASSERT_STR(why, "vary *");
	bst_headers resp, rq;
	hdrs(&resp, "vary: *");
	hdrs(&rq, "");
	ASSERT(!bst_cache_key_vary_match((bst_str){ "", 0 }, &resp, &rq));
}

TEST(vary_normalized) /* 4.1 */
{
	bst_headers resp, a, b, c;
	hdrs(&resp, "vary: Accept-Language");
	hdrs(&a, "accept-language:  en,   fr ");
	hdrs(&b, "Accept-Language: en, fr");
	hdrs(&c, "accept-language: de");
	char buf[256];
	int n = bst_cache_vary_data(&resp, &a, 0, buf, sizeof buf);
	ASSERT(n > 0);
	bst_str st = { buf, (uint32_t)n };
	ASSERT(bst_cache_key_vary_match(st, &resp, &b));
	ASSERT(!bst_cache_key_vary_match(st, &resp, &c));
	bst_cache_policy_cfg lim = CFG;
	lim.vary_limit = 1;
	const char *why;
	ASSERT(!stores(BST_M_GET, "", 200, "cache-control: max-age=6\nvary: a, b", &lim, &why));
	ASSERT_STR(why, "vary limit");
}

TEST(unsafe_invalidates) /* 4.4 */
{
	ASSERT(bst_cache_invalidates(BST_M_POST, 200));
	ASSERT(bst_cache_invalidates(BST_M_PUT, 204));
	ASSERT(bst_cache_invalidates(BST_M_DELETE, 302));
	ASSERT(!bst_cache_invalidates(BST_M_POST, 500));
	ASSERT(!bst_cache_invalidates(BST_M_GET, 200));
	ASSERT(!stores(BST_M_POST, "", 200, "cache-control: max-age=60", NULL, NULL));
}

TEST(partial_not_stored)
{
	const char *why;
	ASSERT(!stores(BST_M_GET, "", 206, "cache-control: max-age=60", NULL, &why));
	ASSERT_STR(why, "partial");
}

TEST(malformed_cc) /* 1.2.2, 4.2.1 */
{
	const char *t[] = { "cache-control: max-age=abc", "cache-control: max-age=-5",
			    "cache-control: max-age=99999999999", "cache-control: max-age=5, max-age=9",
			    "cache-control: max-age=\"5" };
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
		bst_headers h;
		hdrs(&h, t[i]);
		bst_freshness f;
		bst_cache_freshness(200, &h, &CFG, 0, &f);
		ASSERT_EQ(f.lifetime, 0);
	}
	bst_cache_control cc; /* unknown and odd elements are skipped, the rest still counts */
	bst_cc_init(&cc);
	bst_cc_parse_value(BST_S(" ,foo=\"a,b\" , max-age=10 ,, x y, PUBLIC"), &cc);
	ASSERT(!cc.invalid);
	ASSERT_EQ(cc.max_age, 10);
	ASSERT(cc.pub);
}

TEST(merge_304) /* 4.3.4 */
{
	bst_headers st, r;
	hdrs(&st, "content-type: text/plain\ncontent-length: 5\netag: \"a\"\ncache-control: max-age=1");
	hdrs(&r, "cache-control: max-age=99\ncontent-length: 0\ntransfer-encoding: chunked\nx-new: 1");
	ASSERT_EQ(bst_cache_merge_304(&st, &r), 0);
	ASSERT(bst_str_eq(bst_headers_get(&st, BST_H_CACHE_CONTROL)->value, BST_S("max-age=99")));
	ASSERT_EQ(bst_headers_count(&st, BST_H_CACHE_CONTROL), 1);
	ASSERT_EQ(bst_headers_get(&st, BST_H_CONTENT_LENGTH)->value.p[0], '5');
	ASSERT(bst_headers_get(&st, BST_H_TRANSFER_ENCODING) == NULL);
	ASSERT(bst_headers_get_name(&st, BST_S("x-new")) != NULL);
	ASSERT(bst_headers_get(&st, BST_H_CONTENT_TYPE) != NULL);
}

TAP_MAIN()

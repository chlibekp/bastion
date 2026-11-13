/* libFuzzer harness for Cache-Control parsing and the cache policy. Properties: no crash or hang;
 * every delta-seconds parsed is BST_CC_NONE or within [0, 2^31]; Vary data never exceeds its
 * buffer; freshness of an invalid field is 0. Input: the bytes are split at the first NUL into a
 * response Cache-Control value and a Vary value. */
#include "cache/policy.h"
#include "http/cache_control.h"

#include <stdlib.h>
#include <string.h>

static void check(int64_t v)
{
	if (v != BST_CC_NONE && (v < 0 || v > 2147483648LL))
		abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t len)
{
	if (len > 8192)
		return 0;
	const char *p = (const char *)d;
	const char *z = memchr(p, 0, len);
	size_t a = z ? (size_t)(z - p) : len;
	bst_str cc_v = { p, (uint32_t)a };
	bst_str vary_v = { z ? z + 1 : p, z ? (uint32_t)(len - a - 1) : 0 };
	bst_cache_control cc;
	bst_cc_init(&cc);
	bst_cc_parse_value(cc_v, &cc);
	check(cc.max_age), check(cc.s_maxage), check(cc.max_stale), check(cc.min_fresh);
	check(cc.swr), check(cc.sie);

	bst_arena *ar = bst_arena_new(4096);
	if (ar == NULL)
		return 0;
	bst_headers resp, req;
	bst_headers_init(&resp, ar);
	bst_headers_init(&req, ar);
	bst_headers_add(&resp, BST_S("cache-control"), cc_v);
	bst_headers_add(&resp, BST_S("vary"), vary_v);
	bst_headers_add(&resp, BST_S("expires"), vary_v);
	bst_headers_add(&req, BST_S("accept-language"), cc_v);
	bst_headers_add(&req, BST_S("cache-control"), vary_v);
	bst_cache_policy_cfg cfg = { .heuristic_max = 3600, .vary_limit = 8, .honor_request_cc = true };
	bst_freshness f;
	bst_cache_freshness(200, &resp, &cfg, 1000, &f);
	if (cc.invalid && f.lifetime != 0 && strcmp(f.source, "cdn-cache-control") != 0)
		abort();
	char buf[64];
	int n = bst_cache_vary_data(&resp, &req, 8, buf, sizeof buf);
	if (n > (int)sizeof buf)
		abort();
	bst_req_head rh;
	memset(&rh, 0, sizeof rh);
	rh.method = BST_M_GET;
	rh.headers = req;
	(void)bst_cache_storable(&rh, 200, &resp, &cfg, NULL);
	(void)bst_cache_req_revalidate(&req, &cfg);
	(void)bst_cache_key_vary_match((bst_str){ buf, n > 0 ? (uint32_t)n : 0 }, &resp, &req);
	bst_arena_free(ar);
	return 0;
}

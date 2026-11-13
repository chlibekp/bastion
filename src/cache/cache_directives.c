/* The cache's directives: `cache_store` blocks (where objects live and how the store behaves)
 * and, per scope, `cache` and its companions (how requests use a store). */
#include "cache/policy.h"
#include "config/compile.h"
#include "config/template.h"
#include "config/values.h"
#include "core/cidr.h"
#include "http/http.h"
#include "http/token.h"

#include <stdlib.h>
#include <string.h>

#define MS 1000 /* microseconds per millisecond */
#define SEC 1000000
#define UP1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }
#define DUR(lo, hi) { .kind = BST_T_DURATION, .min = (lo), .max = (hi) }

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static uint64_t arg_size(const bst_directive *d, const bst_ast_node *n)
{
	uint64_t v = 0;
	(void)bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v);
	return v;
}

static uint64_t arg_ms(const bst_directive *d, const bst_ast_node *n)
{
	uint64_t v = 0;
	(void)bst_parse_duration_us(as_str(bst_dir_pos(d, n, 0)), &v);
	return v / 1000;
}

static unsigned arg_uint(const bst_directive *d, const bst_ast_node *n)
{
	int64_t v = 0;
	(void)bst_parse_int(as_str(bst_dir_pos(d, n, 0)), 0, INT32_MAX, &v);
	return (unsigned)v;
}

static bool arg_bool(const bst_directive *d, const bst_ast_node *n)
{
	bool v = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	return v;
}

/* ---- cache_store { } ---- */

static int ap_store(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_cfg_cache_store *s = bst_arena_alloc(c->arena, sizeof *s);
	if (s == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(s, 0, sizeof *s); /* the block's defaults apply as directives */
	s->dirfd = -1;
	s->name = bst_cfg_strdup(c, a->text, a->len, e);
	if (s->name == NULL || bst_cfg_loc_at(c, &a->loc, &s->loc, e) != 0)
		return -1;
	bst_cfg_global *g = c->global;
	if (bst_cfg_push_owned(c, &g->cache_stores, &g->ncache_stores, &g->cache_stores_cap_,
			       sizeof s, &s, e) != 0)
		return -1;
	c->cache_store = s;
	return 0;
}

static const bst_optspec disk_opts[] = {
	{ .key = "size=", .type = { .kind = BST_T_SIZE, .min = 1048576 }, .required = true },
};

static int ap_disk(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_cache_store *s = c->cache_store;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (a->text[0] != '/') {
		bst_err_set(e, "disk: needs an absolute path");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	s->path = bst_cfg_strdup(c, a->text, a->len, e);
	bst_ast_arg v;
	if (bst_dir_opt(d, n, "size=", &v))
		(void)bst_parse_size(as_str(&v), &s->size);
	return s->path == NULL ? -1 : 0;
}

#define AP_STORE(fn, field, conv)                                                         \
	static int fn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e) \
	{                                                                                \
		(void)e;                                                                 \
		c->cache_store->field = conv(d, n);                                      \
		return 0;                                                                \
	}

AP_STORE(ap_max_object, max_object, arg_size)
AP_STORE(ap_min_uses, min_uses, arg_uint)
AP_STORE(ap_inactive, inactive_ms, arg_ms)
AP_STORE(ap_evict_batch, evict_batch, arg_uint)
AP_STORE(ap_scan_rate, scan_rate, arg_uint)
AP_STORE(ap_max_entries, max_entries, arg_uint)
AP_STORE(ap_ram, ram, arg_size)
AP_STORE(ap_ram_max_object, ram_max_object, arg_size)
AP_STORE(ap_lock, lock, arg_bool)
AP_STORE(ap_lock_timeout, lock_timeout_ms, arg_ms)
AP_STORE(ap_lock_max_waiters, lock_max_waiters, arg_uint)
AP_STORE(ap_bg_reval, background_revalidate, arg_bool)

static int post_cache_stores(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	bst_cfg_global *g = &cfg->global;
	for (size_t i = 0; i < g->ncache_stores; i++) {
		bst_cfg_cache_store *s = g->cache_stores[i];
		if (s->path == NULL) {
			bst_err_set(e, "cache_store %s: needs `disk <path> size=<size>`", s->name);
			bst_cfg_err_at(e, bst_cfg_src(c, &s->loc));
			return -1;
		}
		for (size_t j = 0; j < i; j++)
			if (strcmp(g->cache_stores[j]->name, s->name) == 0) {
				bst_err_set(e, "cache_store %s: the name is already used", s->name);
				bst_cfg_err_at(e, bst_cfg_src(c, &s->loc));
				return -1;
			}
		if (s->max_entries == 0) {
			uint64_t n = s->size / 8192;
			s->max_entries = n < 1024 ? 1024 : n > (1u << 24) ? (1u << 24) : n;
		}
	}
	return 0;
}
BST_CFG_POST(post_cache_stores);

/* ---- cache and companions, per scope ---- */

static int ap_cache(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_cfg_cache *cc = &c->common->cache;
	cc->store = NULL;
	cc->store_name = bst_cfg_strdup(c, a->text, a->len, e);
	if (cc->store_name == NULL || bst_cfg_loc_at(c, &a->loc, &cc->loc, e) != 0)
		return -1;
	return 0;
}

static int ap_key(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	c->common->cache.key = bst_tpl_compile_arg(bst_dir_pos(d, n, 0), c->arena, e);
	return c->common->cache.key == NULL ? -1 : 0;
}

static int ap_valid(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	size_t np = bst_dir_npos(d, n);
	const bst_ast_arg *last = bst_dir_pos(d, n, np - 1);
	uint64_t us;
	if (!bst_parse_duration_us(as_str(last), &us)) {
		bst_err_set(e, "cache_valid: the last argument is a time (10m, 1h)");
		bst_cfg_err_at(e, &last->loc);
		return -1;
	}
	for (size_t i = 0; i < (np == 1 ? 1 : np - 1); i++) {
		bst_cache_valid *v = bst_arena_alloc(c->arena, sizeof *v);
		if (v == NULL) {
			bst_err_set(e, "out of memory");
			return -1;
		}
		v->secs = (int64_t)(us / SEC);
		v->status = 200; /* `cache_valid 10m`: 200 only */
		if (np > 1) {
			const bst_ast_arg *a = bst_dir_pos(d, n, i);
			int64_t st;
			if (bst_str_eq(as_str(a), BST_S("any"))) {
				st = 0;
			} else if (!bst_parse_int(as_str(a), 200, 599, &st)) {
				bst_err_set(e, "cache_valid: a status is 200 to 599, or `any`");
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
			v->status = (int)st;
		}
		if (bst_cfg_list_append(c, &c->common->cache.valid, v, e) != 0)
			return -1;
	}
	return 0;
}

static int ap_methods(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint32_t m = 0;
	for (size_t i = 0; i < bst_dir_npos(d, n); i++)
		m |= 1u << bst_method_from(as_str(bst_dir_pos(d, n, i)));
	c->common->cache.methods = m;
	return 0;
}

static int tpl_list(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_cfg_list *l,
		    bst_err *e)
{
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		bst_tpl *t = bst_tpl_compile_arg(bst_dir_pos(d, n, i), c->arena, e);
		if (t == NULL || bst_cfg_list_append(c, l, t, e) != 0)
			return -1;
	}
	return 0;
}

static int ap_bypass(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return tpl_list(c, d, n, &c->common->cache.bypass, e);
}

static int ap_no_store_if(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return tpl_list(c, d, n, &c->common->cache.no_store_if, e);
}

static int ap_ignore(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint32_t m = 0;
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		bst_str v = as_str(bst_dir_pos(d, n, i));
		if (bst_str_eq(v, BST_S("cache-control")))
			m |= BST_CACHE_IGN_CACHE_CONTROL;
		else if (bst_str_eq(v, BST_S("expires")))
			m |= BST_CACHE_IGN_EXPIRES;
		else if (bst_str_eq(v, BST_S("set-cookie")))
			m |= BST_CACHE_IGN_SET_COOKIE;
		else if (bst_str_eq(v, BST_S("vary")))
			m |= BST_CACHE_IGN_VARY;
		else if (bst_str_eq(v, BST_S("cdn-cache-control")))
			m |= BST_CACHE_IGN_CDN_CACHE_CONTROL;
	}
	c->common->cache.ignore = m; /* `none` sets nothing */
	return 0;
}

static int ap_vary_limit(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->cache.vary_limit = arg_uint(d, n);
	return 0;
}

static int ap_status_header(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (bst_str_eq(as_str(a), BST_S("off"))) {
		c->common->cache.status_header = NULL;
		return 0;
	}
	if (!bst_is_token(as_str(a))) {
		bst_err_set(e, "cache_status_header: a header name, or off");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	c->common->cache.status_header = bst_cfg_strdup(c, a->text, a->len, e);
	return c->common->cache.status_header == NULL ? -1 : 0;
}

static int ap_cookies(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->cache.cookies = bst_str_eq(as_str(bst_dir_pos(d, n, 0)), BST_S("strip"))
					   ? BST_CACHE_COOKIES_STRIP
					   : BST_CACHE_COOKIES_NO_STORE;
	return 0;
}

static int ap_honor(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->cache.honor_req_cc = arg_bool(d, n);
	return 0;
}

static int ap_bg_fill(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->cache.background_fill = arg_bool(d, n);
	return 0;
}

static int ap_swr(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->cache.swr_s = (int64_t)(arg_ms(d, n) / 1000);
	return 0;
}

static int ap_sie(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->cache.sie_s = (int64_t)(arg_ms(d, n) / 1000);
	return 0;
}

static int resolve_cache(bst_config *cfg, bst_cfg_ctx *c, bst_cfg_common *cm, bst_err *e)
{
	bst_cfg_cache *cc = &cm->cache;
	if (cc->store_name == NULL || strcmp(cc->store_name, "off") == 0) {
		cc->store = NULL;
		return 0;
	}
	for (size_t i = 0; i < cfg->global.ncache_stores; i++)
		if (strcmp(cfg->global.cache_stores[i]->name, cc->store_name) == 0) {
			cc->store = cfg->global.cache_stores[i];
			return 0;
		}
	bst_err_set(e, "cache %s: no cache_store with that name", cc->store_name);
	bst_cfg_err_at(e, bst_cfg_src(c, &cc->loc));
	return -1;
}

static int resolve_locs(bst_config *cfg, bst_cfg_ctx *c, bst_cfg_location **ls, size_t n, bst_err *e)
{
	for (size_t i = 0; i < n; i++)
		if (resolve_cache(cfg, c, &ls[i]->common, e) != 0 ||
		    resolve_locs(cfg, c, ls[i]->children, ls[i]->nchildren, e) != 0)
			return -1;
	return 0;
}

static int post_cache_refs(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	for (size_t i = 0; i < cfg->global.nservers; i++) {
		bst_cfg_server *s = cfg->global.servers[i];
		if (resolve_cache(cfg, c, &s->common, e) != 0 ||
		    resolve_locs(cfg, c, s->locations, s->nlocations, e) != 0)
			return -1;
	}
	return 0;
}
BST_CFG_POST(post_cache_refs);

static const char *const methods_v[] = { "GET", "HEAD", NULL };
static const char *const ignore_v[] = { "cache-control", "expires", "set-cookie", "vary",
					"cdn-cache-control", "none", NULL };
static const char *const cookies_v[] = { "no_store", "strip", NULL };

#define GSL (BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION)
#define ANY_ARGS(...) .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { __VA_ARGS__ } }

static const bst_directive cache_dirs[] = {
	{ .name = "cache", .contexts = GSL, .apply = ap_cache, .default_value = "off",
	  .doc = "Caches the responses of `proxy` in the named `cache_store` (RFC 9111, as a shared "
		 "cache), or `off`. A hit is answered without the upstream, with Age and Cache-Status "
		 "(RFC 9211), conditional requests (304) and a single Range (206); a stale response "
		 "is revalidated with its validators. Only complete responses are stored: one cut "
		 "short, or failed, never is.",
	  UP1({ .kind = BST_T_STRING }) },
	{ .name = "cache_key", .contexts = GSL, .apply = ap_key,
	  .default_value = "$scheme$host$request_uri",
	  .doc = "What identifies a stored response. Request fields not in the key (and not in the "
		 "response's Vary) must not change the response, or one client could be served "
		 "another's: X-Forwarded-Host and friends are rewritten by the proxy for that reason.",
	  UP1({ .kind = BST_T_TEMPLATE }) },
	{ .name = "cache_valid", .contexts = GSL, .apply = ap_valid, .repeatable = true,
	  .doc = "Freshness for responses with none of their own (no CDN-Cache-Control, s-maxage, "
		 "max-age or Expires): `cache_valid 200 301 10m`, `cache_valid any 1m`, or "
		 "`cache_valid 5m` for 200. Without one, such a response is stored only with "
		 "heuristic freshness (a 200-type response with Last-Modified), never an error.",
	  ANY_ARGS({ .kind = BST_T_STRING }) },
	{ .name = "cache_methods", .contexts = GSL, .apply = ap_methods, .default_value = "GET HEAD",
	  .doc = "Methods answered from the cache. Only GET responses are stored; HEAD is answered "
		 "from a stored GET.",
	  ANY_ARGS({ .kind = BST_T_ENUM, .enum_values = methods_v }) },
	{ .name = "cache_bypass", .contexts = GSL, .apply = ap_bypass, .repeatable = true,
	  .doc = "Templates: when one is non-empty and not \"0\", the request skips the lookup and "
		 "goes to the upstream (its response may still be stored): `cache_bypass "
		 "$cookie_session`.",
	  ANY_ARGS({ .kind = BST_T_TEMPLATE }) },
	{ .name = "cache_no_store_if", .contexts = GSL, .apply = ap_no_store_if, .repeatable = true,
	  .doc = "Templates: when one is non-empty and not \"0\", the response is not stored.",
	  ANY_ARGS({ .kind = BST_T_TEMPLATE }) },
	{ .name = "cache_ignore_headers", .contexts = GSL, .apply = ap_ignore, .default_value = "none",
	  .doc = "Response fields the cache acts as if absent: cache-control, expires, set-cookie "
		 "(stores responses that set cookies: dangerous), vary, cdn-cache-control; or none.",
	  ANY_ARGS({ .kind = BST_T_ENUM, .enum_values = ignore_v }) },
	{ .name = "cache_vary_limit", .contexts = GSL, .apply = ap_vary_limit, .default_value = "8",
	  .doc = "A response whose Vary names more fields than this is not stored (Vary: * never is).",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 64 }) },
	{ .name = "cache_status_header", .contexts = GSL, .apply = ap_status_header,
	  .default_value = "Cache-Status",
	  .doc = "The RFC 9211 field that tells the client what the cache did (hit, fwd=miss, "
		 "stored, ...), or off.",
	  UP1({ .kind = BST_T_STRING }) },
	{ .name = "cache_cookies_policy", .contexts = GSL, .apply = ap_cookies,
	  .default_value = "no_store",
	  .doc = "A response with Set-Cookie: `no_store` (the default) passes it uncached; `strip` "
		 "stores it without its Set-Cookie fields (the client that caused the fill still "
		 "gets them).",
	  UP1({ .kind = BST_T_ENUM, .enum_values = cookies_v }) },
	{ .name = "cache_honor_request_cc", .contexts = GSL, .apply = ap_honor, .default_value = "off",
	  .doc = "on: a client's Cache-Control: no-cache (or max-age=0, or Pragma: no-cache) makes "
		 "the cache revalidate. off (the default): clients can not force load onto the "
		 "upstream.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "cache_background_fill", .contexts = GSL, .apply = ap_bg_fill, .default_value = "off",
	  .doc = "on: when a client leaves while its response is being stored, the response is "
		 "fetched again in the background and stored. off: the fill is dropped. Either way a "
		 "partial object is never stored.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "stale_while_revalidate", .contexts = GSL, .apply = ap_swr, .default_value = "0s",
	  .doc = "How long past its freshness a stored response may be served while one background "
		 "request revalidates it (RFC 5861); the response's own stale-while-revalidate "
		 "counts when longer. Never for must-revalidate, proxy-revalidate, s-maxage or "
		 "no-cache responses.",
	  UP1(DUR(0, 365LL * 86400 * SEC)) },
	{ .name = "stale_if_error", .contexts = GSL, .apply = ap_sie, .default_value = "0s",
	  .doc = "How long past its freshness a stored response may be served when the upstream "
		 "fails (5xx, refused, timed out) (RFC 5861); the response's own stale-if-error "
		 "counts when longer. Cache-Status then says fwd=stale and detail=stale-if-error. "
		 "Never for must-revalidate responses.",
	  UP1(DUR(0, 365LL * 86400 * SEC)) },
};
BST_DIRECTIVES(cache_dirs);

#define CS BST_CTX_CACHE_STORE

static const bst_directive cache_store_dirs[] = {
	{ .name = "cache_store", .contexts = BST_CTX_GLOBAL, .apply = ap_store, .repeatable = true,
	  .child_ctx = CS,
	  .doc = "A named HTTP cache store (`cache name` uses it): one file per object below "
		 "`disk`, a shared index of them, and an optional per-worker RAM tier. Names are "
		 "unique.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } },
		    .block = BST_BLOCK_REQUIRED } },
	{ .name = "disk", .contexts = CS, .apply = ap_disk,
	  .doc = "Directory of the store's objects and its size limit: `disk /var/cache/bastion "
		 "size=50g`. Required. Made at start if missing (owned by `user`) and granted write "
		 "access by the sandbox. Objects are written to tmp/ and renamed into place, so a "
		 "crash never leaves a partial object; least recently used objects are removed by the "
		 "helper to stay under size.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_PATH } },
		    .opts = disk_opts, .nopts = sizeof disk_opts / sizeof disk_opts[0] } },
	{ .name = "max_object", .contexts = CS, .apply = ap_max_object, .default_value = "1g",
	  .doc = "Largest response body stored; a larger one is passed through uncached.",
	  UP1({ .kind = BST_T_SIZE, .min = 1 }) },
	{ .name = "min_uses", .contexts = CS, .apply = ap_min_uses, .default_value = "1",
	  .doc = "Requests for a key before its response is stored: 2 or more keeps one-off URLs out "
		 "of the store.",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 1000 }) },
	{ .name = "inactive", .contexts = CS, .apply = ap_inactive, .default_value = "10m",
	  .doc = "An object not requested for this long is removed, fresh or not.",
	  UP1(DUR(1 * SEC, 365LL * 86400 * SEC)) },
	{ .name = "evict_batch", .contexts = CS, .apply = ap_evict_batch, .default_value = "64",
	  .doc = "Objects the helper removes per eviction round (one round a second).",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 1000000 }) },
	{ .name = "scan_rate", .contexts = CS, .apply = ap_scan_rate, .default_value = "10000",
	  .doc = "Files per second the helper reads at start to rebuild the index. Traffic is served "
		 "meanwhile; an object not yet indexed is a miss.",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 10000000 }) },
	{ .name = "max_entries", .contexts = CS, .apply = ap_max_entries, .default_value = "0",
	  .doc = "Slots of the shared index (about 128 bytes each). 0: one per 8 KiB of `size`, at "
		 "least 1024 and at most 16M. A full index stores nothing new, counted and logged.",
	  UP1({ .kind = BST_T_INT, .min = 0, .max = 1 << 26 }) },
	{ .name = "ram", .contexts = CS, .apply = ap_ram, .default_value = "0",
	  .doc = "Bytes of the RAM tier in front of the disk, split evenly between the workers: each "
		 "worker keeps its own copies, with no locks (a popular object may be held once per "
		 "worker). Scan resistant (S3-FIFO): a one-time crawl does not push out the objects "
		 "in steady use. 0: off.",
	  UP1({ .kind = BST_T_SIZE, .min = 0 }) },
	{ .name = "ram_max_object", .contexts = CS, .apply = ap_ram_max_object, .default_value = "1m",
	  .doc = "Largest body kept in the RAM tier; larger objects are served from disk only.",
	  UP1({ .kind = BST_T_SIZE, .min = 1 }) },
	{ .name = "lock", .contexts = CS, .apply = ap_lock, .default_value = "on",
	  .doc = "Stampede protection: when many requests miss on one key at once, one of them (in "
		 "any worker) fetches it and the others wait for the stored object. A response that "
		 "is not storable releases the waiters at once, and each fetches its own.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "lock_timeout", .contexts = CS, .apply = ap_lock_timeout, .default_value = "5s",
	  .doc = "How long requests wait for another request's fill before going to the upstream "
		 "themselves; also how long a fill whose worker died holds the lock.",
	  UP1(DUR(10 * MS, 600LL * SEC)) },
	{ .name = "lock_max_waiters", .contexts = CS, .apply = ap_lock_max_waiters,
	  .default_value = "4096",
	  .doc = "Requests each worker lets wait on fills at once; more go to the upstream.",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 10000000 }) },
	{ .name = "background_revalidate", .contexts = CS, .apply = ap_bg_reval, .default_value = "on",
	  .doc = "Within stale-while-revalidate, a stale response is served at once and one request "
		 "in the background (across all workers) refreshes it. off: stale responses are "
		 "revalidated in line.",
	  UP1({ .kind = BST_T_BOOL }) },
};
BST_DIRECTIVES(cache_store_dirs);

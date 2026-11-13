/* The cache's directives: `cache_store` blocks (where objects live and how the store behaves)
 * and, per scope, `cache` and its companions (how requests use a store). */
#include "cache/policy.h"
#include "config/compile.h"
#include "config/template.h"
#include "config/values.h"
#include "core/cidr.h"

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
};
BST_DIRECTIVES(cache_store_dirs);

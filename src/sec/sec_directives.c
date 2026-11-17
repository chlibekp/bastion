/* The L7 security directives (Phase 12): `limit_zone` blocks and `limit`, `limit_headers`.
 * Later tasks of the phase add theirs in the files of their own modules. */
#include "config/compile.h"
#include "config/errfmt.h"
#include "config/template.h"
#include "config/values.h"
#include "core/arena.h"
#include "sec/acl.h"
#include "sec/limit.h"

#include <stdlib.h>
#include <string.h>

#define MS 1000
#define SEC 1000000
#define UP1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }
#define GSL (BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION)
#define LZ BST_CTX_LIMIT_ZONE

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static int oom(bst_err *e)
{
	bst_err_set(e, "out of memory");
	return -1;
}

/* ---- limit_zone { } ---- */

static int ap_zone(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_limit_zone *z = bst_arena_alloc(c->arena, sizeof *z);
	if (z == NULL)
		return oom(e);
	memset(z, 0, sizeof *z); /* the block's defaults apply as directives */
	z->key_is_addr = true;
	z->name = bst_cfg_strdup(c, a->text, a->len, e);
	if (z->name == NULL || bst_cfg_loc_at(c, &a->loc, &z->loc, e) != 0)
		return -1;
	bst_cfg_global *g = c->global;
	if (bst_cfg_push_owned(c, &g->limit_zones, &g->nlimit_zones, &g->limit_zones_cap_, sizeof z,
			       &z, e) != 0)
		return -1;
	c->limit_zone = z;
	return 0;
}

static int ap_key(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_limit_zone *z = c->limit_zone;
	if (bst_str_eq(as_str(a), BST_S("$remote_addr"))) {
		z->key_is_addr = true;
		z->key = NULL;
		return 0;
	}
	z->key_is_addr = false;
	z->key = bst_tpl_compile_arg(a, c->arena, e);
	return z->key == NULL ? -1 : 0;
}

static const bst_optspec rate_opts[] = {
	{ .key = "burst=", .type = { .kind = BST_T_INT, .min = 1, .max = 1000000000 } },
};

static int ap_rate(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bst_limit_zone *z = c->limit_zone;
	(void)bst_parse_rate(as_str(bst_dir_pos(d, n, 0)), &z->rate);
	z->rate_set = true;
	z->burst = 1;
	bst_ast_arg v;
	if (bst_dir_opt(d, n, "burst=", &v)) {
		int64_t b = 1;
		(void)bst_parse_int(as_str(&v), 1, 1000000000, &b);
		z->burst = (uint64_t)b;
	}
	return 0;
}

static int ap_size(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint64_t bytes = 0;
	(void)bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &bytes);
	uint64_t slots = bytes / sizeof(bst_limit_slot), p = 64;
	while (p * 2 <= slots && p < (1u << 26))
		p *= 2;
	c->limit_zone->size = (uint32_t)p;
	return 0;
}

static int ap_mode(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->limit_zone->delay = bst_str_eq(as_str(bst_dir_pos(d, n, 0)), BST_S("delay"));
	return 0;
}

static int ap_zstatus(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	int64_t v = 429;
	(void)bst_parse_int(as_str(bst_dir_pos(d, n, 0)), 400, 599, &v);
	c->limit_zone->status = (unsigned)v;
	return 0;
}

static int ap_v6prefix(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	int64_t v = 64;
	(void)bst_parse_int(as_str(bst_dir_pos(d, n, 0)), 1, 128, &v);
	c->limit_zone->ipv6_prefix = (unsigned)v;
	return 0;
}

static int ap_dry_run(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool b = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &b);
	c->limit_zone->dry_run = b;
	return 0;
}

/* ---- limit, limit_headers ---- */

static int ap_limit(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		if (i == 0 && bst_str_eq(as_str(a), BST_S("off"))) {
			if (bst_dir_npos(d, n) > 1) {
				bst_err_set(e, "limit: off takes no zones");
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
			/* an empty list of this scope's own: replace what it inherited */
			c->common->sec.limits = (bst_cfg_list){ .owner_ = c->common };
			return 0;
		}
		bst_limit_ref *r = bst_arena_alloc(c->arena, sizeof *r);
		if (r == NULL)
			return oom(e);
		memset(r, 0, sizeof *r);
		r->name = bst_cfg_strdup(c, a->text, a->len, e);
		if (r->name == NULL || bst_cfg_loc_at(c, &a->loc, &r->loc, e) != 0 ||
		    bst_cfg_list_append(c, &c->common->sec.limits, r, e) != 0)
			return -1;
	}
	return 0;
}

static int ap_limit_headers(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool b = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &b);
	c->common->sec.limit_headers = b;
	return 0;
}

/* ---- allow, deny, allow_file, deny_file, acl_default, limit_conn ---- */

static int add_rule(bst_cfg_ctx *c, bool allow, const bst_cidr *cidr, const bst_cidrset *set, bst_err *e)
{
	bst_acl_rule *r = bst_arena_alloc(c->arena, sizeof *r);
	if (r == NULL)
		return oom(e);
	memset(r, 0, sizeof *r);
	r->allow = allow;
	if (cidr != NULL)
		r->cidr = *cidr;
	r->set = set;
	return bst_cfg_list_append(c, &c->common->sec.acl, r, e);
}

static int ap_allow_deny(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bool allow = strcmp(d->name, "allow") == 0;
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		bst_cidr x;
		if (bst_str_eq(as_str(a), BST_S("all"))) {
			memset(&x, 0, sizeof x);
			x.ip.family = BST_IP_V4;
			if (add_rule(c, allow, &x, NULL, e) != 0)
				return -1;
			x.ip.family = BST_IP_V6;
		} else if (!bst_cidr_parse(as_str(a), &x)) {
			bst_ip ip;
			if (!bst_addr_parse(as_str(a), &ip)) {
				bst_err_set(e, "%s: not an address, CIDR or all", d->name);
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
			x.ip = bst_ip_canon(&ip);
			x.prefix = x.ip.family == BST_IP_V4 ? 32 : 128;
		}
		if (add_rule(c, allow, &x, NULL, e) != 0)
			return -1;
	}
	return 0;
}

/* Sets loaded by this compile, handed to the config's cleanups by the post hook. */
static bst_cidrset **g_sets;
static size_t g_nsets, g_setcap;

static void free_set(void *p)
{
	bst_cidrset_free(p);
}

static int ap_acl_file(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	char *path = bst_cfg_strdup(c, a->text, a->len, e);
	if (path == NULL)
		return -1;
	if (g_nsets == g_setcap) {
		size_t nc = g_setcap ? g_setcap * 2 : 8;
		bst_cidrset **np = realloc(g_sets, nc * sizeof *np);
		if (np == NULL)
			return oom(e);
		g_sets = np;
		g_setcap = nc;
	}
	char why[128];
	size_t cnt = 0;
	bst_cidrset *set = bst_acl_load_file(path, &cnt, why, sizeof why);
	if (set == NULL) {
		bst_err_set(e, "%s: can not load '%s': %s", d->name, path, why);
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	g_sets[g_nsets++] = set;
	return add_rule(c, strcmp(d->name, "allow_file") == 0, NULL, set, e);
}

static int post_acl_sets(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	(void)c;
	for (size_t i = 0; i < g_nsets; i++)
		if (bst_config_on_free(cfg, free_set, g_sets[i], e) != 0)
			return -1;
	g_nsets = 0;
	return 0;
}
BST_CFG_POST(post_acl_sets);

static int ap_acl_default(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->sec.acl_default_deny = bst_str_eq(as_str(bst_dir_pos(d, n, 0)), BST_S("deny"));
	return 0;
}

static const bst_optspec conn_opts[] = {
	{ .key = "per_ip=", .type = { .kind = BST_T_INT, .min = 1, .max = 10000000 } },
	{ .key = "subnet4=", .type = { .kind = BST_T_STRING } },
	{ .key = "subnet6=", .type = { .kind = BST_T_STRING } },
};

/* "<prefix>:<n>" */
static int subnet_opt(const bst_ast_arg *v, unsigned maxp, unsigned *len, unsigned *lim, bst_err *e)
{
	bst_str s = as_str(v);
	const char *colon = memchr(s.p, ':', s.len);
	int64_t p = 0, k = 0;
	if (colon == NULL ||
	    !bst_parse_int((bst_str){ s.p, (uint32_t)(colon - s.p) }, 1, (int64_t)maxp, &p) ||
	    !bst_parse_int((bst_str){ colon + 1, (uint32_t)(s.len - (size_t)(colon - s.p) - 1) }, 1,
			   10000000, &k)) {
		bst_err_set(e, "limit_conn: subnet takes <prefix>:<count>, as subnet4=24:200");
		bst_cfg_err_at(e, &v->loc);
		return -1;
	}
	*len = (unsigned)p;
	*lim = (unsigned)k;
	return 0;
}

static int ap_limit_conn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_connlimit_cfg *cl = &c->common->sec.conn;
	memset(cl, 0, sizeof *cl);
	bst_ast_arg v;
	if (bst_dir_opt(d, n, "per_ip=", &v)) {
		int64_t k = 0;
		(void)bst_parse_int(as_str(&v), 1, 10000000, &k);
		cl->per_ip = (unsigned)k;
	}
	if (bst_dir_opt(d, n, "subnet4=", &v) && subnet_opt(&v, 32, &cl->subnet4_len, &cl->subnet4, e) != 0)
		return -1;
	if (bst_dir_opt(d, n, "subnet6=", &v) && subnet_opt(&v, 128, &cl->subnet6_len, &cl->subnet6, e) != 0)
		return -1;
	cl->set = cl->per_ip > 0 || cl->subnet4 > 0 || cl->subnet6 > 0;
	if (!cl->set) {
		bst_err_set(e, "limit_conn: needs per_ip=, subnet4= or subnet6=");
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	return 0;
}

/* ---- checks across blocks ---- */

static bst_limit_zone *zone_named(const bst_cfg_global *g, const char *name)
{
	for (size_t i = 0; i < g->nlimit_zones; i++)
		if (strcmp(g->limit_zones[i]->name, name) == 0)
			return g->limit_zones[i];
	return NULL;
}

static int resolve_list(bst_cfg_ctx *c, const bst_cfg_global *g, const bst_cfg_list *l, bst_err *e)
{
	for (size_t i = 0; i < l->n; i++) {
		bst_limit_ref *r = (bst_limit_ref *)l->items[i];
		if (r->zone != NULL)
			continue;
		r->zone = zone_named(g, r->name);
		if (r->zone == NULL) {
			bst_err_set(e, "limit: no limit_zone named '%s'", r->name);
			bst_cfg_err_at(e, bst_cfg_src(c, &r->loc));
			return -1;
		}
	}
	return 0;
}

static int resolve_loc(bst_cfg_ctx *c, const bst_cfg_global *g, const bst_cfg_location *l, bst_err *e)
{
	if (resolve_list(c, g, &l->common.sec.limits, e) != 0)
		return -1;
	for (size_t i = 0; i < l->nchildren; i++)
		if (resolve_loc(c, g, l->children[i], e) != 0)
			return -1;
	return 0;
}

static int post_limit_zones(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	bst_cfg_global *g = &cfg->global;
	for (size_t i = 0; i < g->nlimit_zones; i++) {
		bst_limit_zone *z = g->limit_zones[i];
		if (!z->rate_set) {
			bst_err_set(e, "limit_zone %s: needs `rate <n>/s|m`", z->name);
			bst_cfg_err_at(e, bst_cfg_src(c, &z->loc));
			return -1;
		}
		for (size_t j = 0; j < i; j++)
			if (strcmp(g->limit_zones[j]->name, z->name) == 0) {
				bst_err_set(e, "limit_zone %s: the name is already used", z->name);
				bst_cfg_err_at(e, bst_cfg_src(c, &z->loc));
				return -1;
			}
	}
	if (resolve_list(c, g, &g->common.sec.limits, e) != 0)
		return -1;
	for (size_t i = 0; i < g->nservers; i++) {
		const bst_cfg_server *s = g->servers[i];
		if (resolve_list(c, g, &s->common.sec.limits, e) != 0)
			return -1;
		for (size_t j = 0; j < s->nlocations; j++)
			if (s->locations[j]->parent == NULL && resolve_loc(c, g, s->locations[j], e) != 0)
				return -1;
	}
	return 0;
}
BST_CFG_POST(post_limit_zones);

static const char *const mode_v[] = { "reject", "delay", NULL };
static const char *const acl_default_v[] = { "allow", "deny", NULL };

static const bst_directive sec_limit_dirs[] = {
	{ .name = "limit_zone", .contexts = BST_CTX_GLOBAL, .apply = ap_zone, .repeatable = true,
	  .child_ctx = LZ,
	  .doc = "A named request rate limit (`limit name` applies it), shared by every worker: a "
		 "lock-free GCRA table in shared memory. Names are unique.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } },
		    .block = BST_BLOCK_REQUIRED } },
	{ .name = "key", .contexts = LZ, .apply = ap_key, .default_value = "$remote_addr",
	  .doc = "What a bucket counts: $remote_addr (the client address after real_ip, IPv6 cut to "
		 "ipv6_prefix, ::ffff: addresses as IPv4) or any template. Hashed with a random "
		 "SipHash key, so clients can not aim at one slot.",
	  UP1({ .kind = BST_T_TEMPLATE }) },
	{ .name = "rate", .contexts = LZ, .apply = ap_rate,
	  .doc = "The rate and burst: `rate 100/s burst=200`. A new key gets `burst` requests at "
		 "once (1 when unset), then one per 1/rate. Required.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_RATE } },
		    .opts = rate_opts, .nopts = 1 } },
	{ .name = "size", .contexts = LZ, .apply = ap_size, .default_value = "1m",
	  .doc = "Shared memory of the zone, 16 bytes per key (rounded down to a power of two of "
		 "slots, at least 64). A full table replaces its least recently due key.",
	  UP1({ .kind = BST_T_SIZE, .min = 1024, .max = 1ll << 30 }) },
	{ .name = "mode", .contexts = LZ, .apply = ap_mode, .default_value = "reject",
	  .doc = "reject: past the burst, refuse with `status` and Retry-After. delay: hold up to "
		 "another burst of requests until each conforms, refuse past that.",
	  UP1({ .kind = BST_T_ENUM, .enum_values = mode_v }) },
	{ .name = "status", .contexts = LZ, .apply = ap_zstatus, .default_value = "429",
	  .doc = "The status of a refused request.",
	  UP1({ .kind = BST_T_INT, .min = 400, .max = 599 }) },
	{ .name = "ipv6_prefix", .contexts = LZ, .apply = ap_v6prefix, .default_value = "64",
	  .doc = "IPv6 clients are keyed by this prefix: addresses rotated inside one /64 are one "
		 "client.",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 128 }) },
	{ .name = "dry_run", .contexts = LZ, .apply = ap_dry_run, .default_value = "off",
	  .doc = "on: requests over the limit are logged and counted "
		 "(bastion_limit_dry_run_total) but never refused or delayed.",
	  UP1({ .kind = BST_T_BOOL }) },
};
BST_DIRECTIVES(sec_limit_dirs);

static const bst_directive sec_scope_dirs[] = {
	{ .name = "limit", .contexts = GSL, .apply = ap_limit,
	  .doc = "Applies these limit_zone names to the requests of the scope, in order; the first "
		 "that refuses answers. A scope that names its own replaces the inherited list; "
		 "`limit off` clears it.",
	  .args = { .min_args = 1, .max_args = 16, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "limit_headers", .contexts = GSL, .apply = ap_limit_headers, .default_value = "off",
	  .doc = "on: responses carry the RateLimit and RateLimit-Policy fields "
		 "(draft-ietf-httpapi-ratelimit-headers) of the first zone of `limit`.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "allow", .contexts = GSL, .apply = ap_allow_deny, .repeatable = true,
	  .doc = "Lets these addresses or CIDRs (or all) in. Rules are checked in order and the "
		 "first that matches decides; a scope that writes rules replaces the inherited ones. "
		 "Server-scope rules apply at accept (the connection is closed before TLS), location "
		 "rules per request (403). The address is the one real_ip trusts.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "deny", .contexts = GSL, .apply = ap_allow_deny, .repeatable = true,
	  .doc = "Refuses these addresses or CIDRs (or all); see allow for the order.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "allow_file", .contexts = GSL, .apply = ap_acl_file, .repeatable = true,
	  .doc = "An allow rule matching any address or CIDR the file lists, one per line, # "
		 "comments. Read at load into a prefix tree (a million entries load in about a second).",
	  UP1({ .kind = BST_T_PATH }) },
	{ .name = "deny_file", .contexts = GSL, .apply = ap_acl_file, .repeatable = true,
	  .doc = "A deny rule matching any address or CIDR the file lists; as allow_file.",
	  UP1({ .kind = BST_T_PATH }) },
	{ .name = "acl_default", .contexts = GSL, .apply = ap_acl_default, .default_value = "allow",
	  .doc = "What an address no allow or deny rule matches gets.",
	  UP1({ .kind = BST_T_ENUM, .enum_values = acl_default_v }) },
	{ .name = "limit_conn", .contexts = BST_CTX_GLOBAL | BST_CTX_SERVER, .apply = ap_limit_conn,
	  .doc = "Open connections per client across all workers: `limit_conn per_ip=20 "
		 "subnet4=24:200 subnet6=48:200`. Read on a listener's default server. Past a limit "
		 "the connection is closed at accept, before TLS. Peers in real_ip_from are not "
		 "limited (their connections carry many clients).",
	  .args = { .min_args = 0, .max_args = 0, .opts = conn_opts, .nopts = 3 } },
};
BST_DIRECTIVES(sec_scope_dirs);

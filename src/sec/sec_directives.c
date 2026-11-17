/* The L7 security directives (Phase 12): `limit_zone` blocks and `limit`, `limit_headers`.
 * Later tasks of the phase add theirs in the files of their own modules. */
#include "config/compile.h"
#include "config/errfmt.h"
#include "config/template.h"
#include "config/values.h"
#include "core/arena.h"
#include "sec/acl.h"
#include "sec/block.h"
#include "sec/challenge.h"
#include "sec/limit.h"
#include "sec/waf.h"

#include <stdio.h>
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

/* ---- escalate, escalation_ceiling, escalation_allow ---- */

static const bst_optspec esc_opts[] = {
	{ .key = "after=", .type = { .kind = BST_T_INT, .min = 1, .max = 100000 } },
	{ .key = "window=", .type = { .kind = BST_T_DURATION, .min = 1 * SEC, .max = 86400ll * SEC } },
	{ .key = "block=", .type = { .kind = BST_T_DURATION, .min = 1 * SEC, .max = 86400ll * SEC } },
};

/* The escalate settings of the block this directive is in. */
static bst_escalate_cfg *esc_target(bst_cfg_ctx *c)
{
	if (c->kind == LZ)
		return &c->limit_zone->esc;
	if (c->kind == BST_CTX_H2_ABUSE)
		return &c->common->http.h2.abuse.esc;
	if (c->kind == BST_CTX_WAF_RULE)
		return &c->waf_rule->esc;
	return NULL;
}

static int ap_escalate(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_escalate_cfg *x = esc_target(c);
	if (x == NULL) {
		bst_err_set(e, "escalate: not inside limit_zone, waf_rule or http2_abuse");
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	bst_ast_arg v;
	int64_t after = 0;
	if (!bst_dir_opt(d, n, "after=", &v) || !bst_parse_int(as_str(&v), 1, 100000, &after)) {
		bst_err_set(e, "escalate: needs after=<strikes>, as escalate after=20 window=10s block=10m");
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	x->after = (unsigned)after;
	x->window_us = 10ull * SEC;
	x->block_us = 600ull * SEC;
	if (bst_dir_opt(d, n, "window=", &v))
		(void)bst_parse_duration_us(as_str(&v), &x->window_us);
	if (bst_dir_opt(d, n, "block=", &v))
		(void)bst_parse_duration_us(as_str(&v), &x->block_us);
	return 0;
}

static int ap_esc_ceiling(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	int64_t v = BST_BLOCK_CEILING_DEFAULT;
	(void)bst_parse_int(as_str(bst_dir_pos(d, n, 0)), 1, BST_BLOCK_CEILING_MAX, &v);
	c->global->escalation_ceiling = (unsigned)v;
	return 0;
}

static int ap_esc_allow(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_global *g = c->global;
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		bst_cidr x;
		if (!bst_cidr_parse(as_str(a), &x)) {
			bst_ip ip;
			if (!bst_addr_parse(as_str(a), &ip)) {
				bst_err_set(e, "escalation_allow: not an address or CIDR");
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
			x.ip = ip;
			x.prefix = ip.family == BST_IP_V4 ? 32 : 128;
		}
		if (bst_cfg_push_owned(c, &g->escalation_allow, &g->nescalation_allow, &g->escalation_allow_cap_,
				       sizeof x, &x, e) != 0)
			return -1;
	}
	return 0;
}

static const bst_directive sec_esc_dirs[] = {
	{ .name = "escalate", .contexts = LZ | BST_CTX_H2_ABUSE | BST_CTX_WAF_RULE, .apply = ap_escalate,
	  .doc = "Turns repeated refusals into a block: `escalate after=20 window=10s block=10m`. "
		 "When one client (IPv4 address, IPv6 prefix) collects `after` strikes of this rule "
		 "within `window` across all workers, master blocks it for `block` (window 10s and "
		 "block 10m when unset). Blocked clients are closed at accept and refused per request. "
		 "Addresses in escalation_allow or real_ip_from are never blocked; an address from a "
		 "PROXY header or real_ip is blocked at L7 only.",
	  .args = { .min_args = 0, .max_args = 0, .opts = esc_opts, .nopts = 3 } },
	{ .name = "escalation_ceiling", .contexts = BST_CTX_GLOBAL, .apply = ap_esc_ceiling,
	  .default_value = "10000",
	  .doc = "The most blocks active at once. Past it new block requests are refused and counted "
		 "(bastion_escalate_refused_total{reason=\"ceiling\"}); existing blocks stay until "
		 "their TTL.",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = BST_BLOCK_CEILING_MAX }) },
	{ .name = "escalation_allow", .contexts = BST_CTX_GLOBAL, .apply = ap_esc_allow, .repeatable = true,
	  .doc = "Addresses or CIDRs escalation never blocks (monitoring, partners). Every real_ip_from "
		 "CIDR is exempt as well.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_STRING } } } },
};
BST_DIRECTIVES(sec_esc_dirs);

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

/* ---- waf_rule { match; action; escalate; }, waf, rule_mode ---- */

#define WR BST_CTX_WAF_RULE

static int ap_waf_rule(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_waf_rule *r = bst_arena_alloc(c->arena, sizeof *r);
	if (r == NULL)
		return oom(e);
	memset(r, 0, sizeof *r);
	r->name = bst_cfg_strdup(c, a->text, a->len, e);
	if (r->name == NULL || bst_cfg_loc_at(c, &a->loc, &r->loc, e) != 0)
		return -1;
	bst_cfg_global *g = c->global;
	if (bst_cfg_push_owned(c, &g->waf_rules, &g->nwaf_rules, &g->waf_rules_cap_, sizeof r, &r, e) != 0)
		return -1;
	c->waf_rule = r;
	return 0;
}

static int ap_match(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_waf_rule *r = c->waf_rule;
	bst_waf_match m;
	char why[256];
	size_t np = bst_dir_npos(d, n);
	bst_str v = np > 2 ? as_str(bst_dir_pos(d, n, 2)) : (bst_str){ NULL, 0 };
	if (bst_waf_match_parse(&m, as_str(bst_dir_pos(d, n, 0)), as_str(bst_dir_pos(d, n, 1)),
				np > 2 ? &v : NULL, c->arena, why, sizeof why) != 0) {
		bst_err_set(e, "match: %s", why);
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	if (bst_cfg_push_owned(c, &r->m, &r->nm, &r->cap_, sizeof m, &m, e) != 0) {
		bst_waf_match_free(&m);
		return -1;
	}
	return 0;
}

static int ap_action(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_waf_rule *r = c->waf_rule;
	bst_str what = as_str(bst_dir_pos(d, n, 0));
	size_t np = bst_dir_npos(d, n);
	const bst_ast_arg *arg = np > 1 ? bst_dir_pos(d, n, 1) : NULL;
	r->action_set = true;
	r->status = 403;
	if (bst_str_eq(what, BST_S("deny"))) {
		r->action = BST_WAF_DENY;
		if (arg != NULL) {
			int64_t st = 0;
			if (!bst_parse_int(as_str(arg), 400, 599, &st)) {
				bst_err_set(e, "action deny: the status is 400..599");
				bst_cfg_err_at(e, &arg->loc);
				return -1;
			}
			r->status = (unsigned)st;
		}
		return 0;
	}
	if (bst_str_eq(what, BST_S("limit"))) {
		if (arg == NULL) {
			bst_err_set(e, "action limit: needs a limit_zone name");
			bst_cfg_err_at(e, &n->loc);
			return -1;
		}
		r->action = BST_WAF_LIMIT;
		r->zone_name = bst_cfg_strdup(c, arg->text, arg->len, e);
		return r->zone_name == NULL ? -1 : 0;
	}
	if (arg != NULL) {
		bst_err_set(e, "action %.*s takes no argument", (int)what.len, what.p);
		bst_cfg_err_at(e, &arg->loc);
		return -1;
	}
	if (bst_str_eq(what, BST_S("allow")))
		r->action = BST_WAF_ALLOW;
	else if (bst_str_eq(what, BST_S("log")))
		r->action = BST_WAF_NONE;
	else if (bst_str_eq(what, BST_S("challenge")))
		r->action = BST_WAF_CHALLENGE;
	else {
		bst_err_set(e, "action: allow, deny [status], log, challenge or limit <zone>");
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	return 0;
}

static int ap_waf(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		if (i == 0 && bst_str_eq(as_str(a), BST_S("off"))) {
			if (bst_dir_npos(d, n) > 1) {
				bst_err_set(e, "waf: off takes no rules");
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
			c->common->sec.waf = (bst_cfg_list){ .owner_ = c->common };
			return 0;
		}
		bst_waf_ref *r = bst_arena_alloc(c->arena, sizeof *r);
		if (r == NULL)
			return oom(e);
		memset(r, 0, sizeof *r);
		r->name = bst_cfg_strdup(c, a->text, a->len, e);
		if (r->name == NULL || bst_cfg_loc_at(c, &a->loc, &r->loc, e) != 0 ||
		    bst_cfg_list_append(c, &c->common->sec.waf, r, e) != 0)
			return -1;
	}
	return 0;
}

static int ap_rule_mode(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->sec.waf_log = bst_str_eq(as_str(bst_dir_pos(d, n, 0)), BST_S("log"));
	return 0;
}

static void free_rule(void *p)
{
	bst_waf_rule *r = p;
	for (size_t i = 0; i < r->nm; i++)
		bst_waf_match_free(&r->m[i]);
}

static int resolve_waf(bst_cfg_ctx *c, const bst_cfg_global *g, const bst_cfg_list *l, bst_err *e)
{
	for (size_t i = 0; i < l->n; i++) {
		bst_waf_ref *r = (bst_waf_ref *)l->items[i];
		for (size_t j = 0; r->rule == NULL && j < g->nwaf_rules; j++)
			if (strcmp(g->waf_rules[j]->name, r->name) == 0)
				r->rule = g->waf_rules[j];
		if (r->rule == NULL) {
			bst_err_set(e, "waf: no waf_rule named '%s'", r->name);
			bst_cfg_err_at(e, bst_cfg_src(c, &r->loc));
			return -1;
		}
	}
	return 0;
}

static int post_waf(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	bst_cfg_global *g = &cfg->global;
	for (size_t i = 0; i < g->nwaf_rules; i++) {
		bst_waf_rule *r = g->waf_rules[i];
		if (bst_config_on_free(cfg, free_rule, r, e) != 0)
			return -1;
		for (size_t j = 0; j < i; j++)
			if (strcmp(g->waf_rules[j]->name, r->name) == 0) {
				bst_err_set(e, "waf_rule %s: the name is already used", r->name);
				bst_cfg_err_at(e, bst_cfg_src(c, &r->loc));
				return -1;
			}
		if (r->nm == 0 || !r->action_set) {
			bst_err_set(e, "waf_rule %s: needs at least one `match` and an `action`", r->name);
			bst_cfg_err_at(e, bst_cfg_src(c, &r->loc));
			return -1;
		}
		if (r->action == BST_WAF_LIMIT && (r->zone = zone_named(g, r->zone_name)) == NULL) {
			bst_err_set(e, "waf_rule %s: no limit_zone named '%s'", r->name, r->zone_name);
			bst_cfg_err_at(e, bst_cfg_src(c, &r->loc));
			return -1;
		}
		bst_waf_rule_order(r);
	}
	if (resolve_waf(c, g, &g->common.sec.waf, e) != 0)
		return -1;
	for (size_t i = 0; i < g->nservers; i++) {
		const bst_cfg_server *s = g->servers[i];
		if (resolve_waf(c, g, &s->common.sec.waf, e) != 0)
			return -1;
		for (size_t j = 0; j < s->nlocations; j++)
			if (resolve_waf(c, g, &s->locations[j]->common.sec.waf, e) != 0)
				return -1;
	}
	return 0;
}
BST_CFG_POST(post_waf);

static const char *const rule_mode_v[] = { "enforce", "log", NULL };

static const bst_directive sec_waf_dirs[] = {
	{ .name = "waf_rule", .contexts = BST_CTX_GLOBAL, .apply = ap_waf_rule, .repeatable = true,
	  .child_ctx = WR,
	  .doc = "A named request rule (`waf name` applies it): one or more `match` lines that must "
		 "all hold and one `action`. Checked after routing, before the handler. See "
		 "src/sec/waf.h for the subjects and operators.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } },
		    .block = BST_BLOCK_REQUIRED } },
	{ .name = "match", .contexts = WR, .apply = ap_match, .repeatable = true,
	  .doc = "`match <subject> <op> [value]`. Subjects: path (normalized), uri, query, arg:NAME, "
		 "header:NAME, cookie:NAME, method, host, ip, ja4, content_type, content_length, "
		 "user_agent, protocol, tls_version. Operators: = != ~ !~ prefix suffix contains "
		 "in_cidr in_file > < missing exists. Repeated headers, arguments and cookies: any "
		 "value matching decides (any value not matching, for != and !~).",
	  .args = { .min_args = 2, .max_args = 3,
		    .pos = { { .kind = BST_T_STRING }, { .kind = BST_T_STRING }, { .kind = BST_T_STRING } } } },
	{ .name = "action", .contexts = WR, .apply = ap_action,
	  .doc = "What a match does: allow (skip the remaining rules), deny [status] (403), log (log "
		 "and go on), challenge (the proof-of-work page) or limit <zone>. The first rule that "
		 "matches with anything but log decides.",
	  .args = { .min_args = 1, .max_args = 2, .pos = { { .kind = BST_T_STRING }, { .kind = BST_T_STRING } } } },
	{ .name = "waf", .contexts = GSL, .apply = ap_waf,
	  .doc = "The waf_rule names checked for the scope's requests, in order. A scope that names "
		 "its own replaces the inherited list; `waf off` clears it.",
	  .args = { .min_args = 1, .max_args = 64, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "rule_mode", .contexts = GSL, .apply = ap_rule_mode, .default_value = "enforce",
	  .doc = "log: the scope's waf rules only log what they would have done (`waf: rule NAME "
		 "would ...`); enforce acts on them.",
	  UP1({ .kind = BST_T_ENUM, .enum_values = rule_mode_v }) },
};
BST_DIRECTIVES(sec_waf_dirs);

/* ---- challenge ---- */

static bst_challenge_cfg *chal(bst_cfg_ctx *c)
{
	return &c->common->sec.challenge;
}

static int ap_challenge(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bst_str v = as_str(bst_dir_pos(d, n, 0));
	chal(c)->mode = bst_str_eq(v, BST_S("on")) ? BST_CHAL_ON : bst_str_eq(v, BST_S("auto")) ? BST_CHAL_AUTO : BST_CHAL_OFF;
	return 0;
}

static int ap_chal_page(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	char *path = bst_cfg_strdup(c, a->text, a->len, e);
	if (path == NULL)
		return -1;
	char why[128];
	bool warn = false;
	size_t len = 0;
	const char *page = bst_challenge_load_page(path, c->arena, &len, &warn, why, sizeof why);
	if (page == NULL) {
		bst_err_set(e, "challenge_page: can not load '%s': %s", path, why);
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	if (warn)
		bst_cfg_warn(c, n, "challenge_page '%s' has no {{bastion_challenge}} placeholder: the page gets "
				   "no token and no script, so no client can pass", path);
	chal(c)->page = page;
	chal(c)->page_len = len;
	return 0;
}

static int ap_chal_int(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	int64_t v = 0;
	(void)bst_parse_int(as_str(bst_dir_pos(d, n, 0)), 0, 1000000, &v);
	if (strcmp(d->name, "challenge_difficulty") == 0)
		chal(c)->difficulty = (unsigned)v;
	else if (strcmp(d->name, "challenge_ip_prefix4") == 0)
		chal(c)->prefix4 = (unsigned)v;
	else
		chal(c)->prefix6 = (unsigned)v;
	return 0;
}

static int ap_chal_ttl(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint64_t us = 0;
	(void)bst_parse_duration_us(as_str(bst_dir_pos(d, n, 0)), &us);
	if (strcmp(d->name, "challenge_pass_ttl") == 0)
		chal(c)->pass_ttl_s = us / SEC;
	else
		chal(c)->token_ttl_s = us / SEC;
	return 0;
}

static int ap_chal_allow(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		bst_cidr *x = bst_arena_alloc(c->arena, sizeof *x);
		if (x == NULL)
			return oom(e);
		if (!bst_cidr_parse(as_str(a), x)) {
			bst_ip ip;
			if (!bst_addr_parse(as_str(a), &ip)) {
				bst_err_set(e, "challenge_allow: not an address or CIDR");
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
			x->ip = ip;
			x->prefix = ip.family == BST_IP_V4 ? 32 : 128;
		}
		if (x->ip.family == BST_IP_V6 && bst_ip_canon(&x->ip).family == BST_IP_V4 && x->prefix >= 96) {
			x->ip = bst_ip_canon(&x->ip); /* ::ffff:a.b.c.d/p is the IPv4 network */
			x->prefix = (uint8_t)(x->prefix - 96);
		}
		if (bst_cfg_list_append(c, &c->common->sec.challenge_allow, x, e) != 0)
			return -1;
	}
	return 0;
}

static int ap_chal_cookie(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	for (size_t i = 0; i < a->len; i++) {
		char ch = a->text[i];
		if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' ||
		      ch == '-')) {
			bst_err_set(e, "challenge_cookie_name: letters, digits, _ and - only");
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
	}
	chal(c)->cookie_name = bst_cfg_strdup(c, a->text, a->len, e);
	return chal(c)->cookie_name == NULL ? -1 : 0;
}

static int ap_chal_escalate(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_escalate_cfg *x = &chal(c)->esc;
	bst_ast_arg v;
	int64_t after = 0;
	if (!bst_dir_opt(d, n, "after=", &v) || !bst_parse_int(as_str(&v), 1, 100000, &after)) {
		bst_err_set(e, "challenge_escalate: needs after=<strikes>");
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	x->after = (unsigned)after;
	x->window_us = 10ull * SEC;
	x->block_us = 600ull * SEC;
	if (bst_dir_opt(d, n, "window=", &v))
		(void)bst_parse_duration_us(as_str(&v), &x->window_us);
	if (bst_dir_opt(d, n, "block=", &v))
		(void)bst_parse_duration_us(as_str(&v), &x->block_us);
	return 0;
}

static int ap_chal_auto(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bst_cfg_global *g = c->global;
	bst_str v = as_str(bst_dir_pos(d, n, 0));
	if (strcmp(d->name, "challenge_auto_hold") == 0) {
		uint64_t us = 60ull * SEC;
		(void)bst_parse_duration_us(v, &us);
		g->challenge_auto_hold_s = us / SEC;
		return 0;
	}
	int64_t x = 0;
	(void)bst_parse_int(v, 0, 1000000000, &x);
	if (strcmp(d->name, "challenge_auto_rps") == 0)
		g->challenge_auto_rps = (uint64_t)x;
	else
		g->challenge_auto_block_rate = (uint64_t)x;
	return 0;
}

static bool has_auto(const bst_cfg_common *cm)
{
	return cm->sec.challenge.mode == BST_CHAL_AUTO;
}

/* `challenge auto` needs a threshold to ever turn on. */
static int post_challenge(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	(void)c;
	bst_cfg_global *g = &cfg->global;
	if (g->challenge_auto_hold_s == 0)
		g->challenge_auto_hold_s = 60;
	if (g->challenge_auto_rps > 0 || g->challenge_auto_block_rate > 0)
		return 0;
	bool used = has_auto(&g->common);
	for (size_t i = 0; !used && i < g->nservers; i++) {
		used = has_auto(&g->servers[i]->common);
		for (size_t j = 0; !used && j < g->servers[i]->nlocations; j++)
			used = has_auto(&g->servers[i]->locations[j]->common);
	}
	if (used) {
		bst_err_set(e, "challenge auto: set challenge_auto_rps or challenge_auto_block_rate, or it never turns on");
		return -1;
	}
	return 0;
}
BST_CFG_POST(post_challenge);

static const char *const challenge_v[] = { "off", "on", "auto", NULL };

static const bst_directive sec_challenge_dirs[] = {
	{ .name = "challenge", .contexts = GSL, .apply = ap_challenge, .default_value = "off",
	  .doc = "on: requests without a valid pass cookie get a proof-of-work page (403, no-store), or "
		 "a plain-text 403 when they do not accept text/html. auto: the same, only while "
		 "Bastion is under attack (challenge_auto_rps). The answer goes to POST "
		 "/.bastion/challenge, which sets the pass and redirects to the original path. "
		 "Nothing is stored on the server. See docs/challenge.md.",
	  UP1({ .kind = BST_T_ENUM, .enum_values = challenge_v }) },
	{ .name = "challenge_page", .contexts = GSL, .apply = ap_chal_page,
	  .doc = "An HTML file used instead of the built-in page, read at load (at most 1 MiB). "
		 "{{bastion_challenge}} is replaced by the script that defines window.BASTION, "
		 "{{bastion_nonce}} by the response's CSP nonce. A page without the first is a "
		 "warning at -t.",
	  UP1({ .kind = BST_T_PATH }) },
	{ .name = "challenge_difficulty", .contexts = GSL, .apply = ap_chal_int, .default_value = "16",
	  .doc = "Leading zero bits the SHA-256 of the answer must have: each bit doubles the work "
		 "(16 is about 65,000 hashes, well under a second in a browser).",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 32 }) },
	{ .name = "challenge_pass_ttl", .contexts = GSL, .apply = ap_chal_ttl, .default_value = "1h",
	  .doc = "How long a pass cookie is valid.",
	  UP1({ .kind = BST_T_DURATION, .min = 60ll * SEC, .max = 30ll * 86400 * SEC }) },
	{ .name = "challenge_token_ttl", .contexts = GSL, .apply = ap_chal_ttl, .default_value = "5m",
	  .doc = "How long a page's token can be answered.",
	  UP1({ .kind = BST_T_DURATION, .min = 10ll * SEC, .max = 86400ll * SEC }) },
	{ .name = "challenge_ip_prefix4", .contexts = GSL, .apply = ap_chal_int, .default_value = "24",
	  .doc = "Tokens and passes are bound to the client's IPv4 network of this prefix.",
	  UP1({ .kind = BST_T_INT, .min = 8, .max = 32 }) },
	{ .name = "challenge_ip_prefix6", .contexts = GSL, .apply = ap_chal_int, .default_value = "56",
	  .doc = "Tokens and passes are bound to the client's IPv6 network of this prefix.",
	  UP1({ .kind = BST_T_INT, .min = 16, .max = 128 }) },
	{ .name = "challenge_allow", .contexts = GSL, .apply = ap_chal_allow, .repeatable = true,
	  .doc = "Addresses or CIDRs never challenged (API clients, monitoring): the answer for "
		 "clients that can not run the page. A scope that writes its own replaces the "
		 "inherited list.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "challenge_cookie_name", .contexts = GSL, .apply = ap_chal_cookie,
	  .default_value = "bastion_pass",
	  .doc = "The name of the pass cookie (HttpOnly, SameSite=Lax, Secure over TLS).",
	  UP1({ .kind = BST_T_STRING }) },
	{ .name = "challenge_escalate", .contexts = GSL, .apply = ap_chal_escalate,
	  .doc = "Invalid answers to /.bastion/challenge count as strikes: `challenge_escalate "
		 "after=20 window=10s block=10m` (see escalate).",
	  .args = { .min_args = 0, .max_args = 0, .opts = esc_opts, .nopts = 3 } },
	{ .name = "challenge_auto_rps", .contexts = BST_CTX_GLOBAL, .apply = ap_chal_auto, .default_value = "0",
	  .doc = "challenge auto turns on when the last second's requests, across all workers, reach "
		 "this many (the helper samples once a second). 0: not used.",
	  UP1({ .kind = BST_T_INT, .min = 0, .max = 1000000000 }) },
	{ .name = "challenge_auto_block_rate", .contexts = BST_CTX_GLOBAL, .apply = ap_chal_auto,
	  .default_value = "0",
	  .doc = "challenge auto also turns on when the last second's refusals (limit_zone rejects, "
		 "escalation blocks, waf denies) reach this many. 0: not used.",
	  UP1({ .kind = BST_T_INT, .min = 0, .max = 1000000000 }) },
	{ .name = "challenge_auto_hold", .contexts = BST_CTX_GLOBAL, .apply = ap_chal_auto, .default_value = "60s",
	  .doc = "challenge auto turns off only after both rates stayed below their thresholds this "
		 "long, so an oscillating load does not make it flap.",
	  UP1({ .kind = BST_T_DURATION, .min = 1ll * SEC, .max = 86400ll * SEC }) },
};
BST_DIRECTIVES(sec_challenge_dirs);

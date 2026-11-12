/* Routing directives (Phase 5): which server answers a request (unknown_host, the default_server
 * flag of listen, checked here) and what a location does with it (added by the later tasks of
 * the phase in this file). */
#include "config/compile.h"
#include "config/errfmt.h"
#include "config/values.h"
#include "core/str.h"
#include "route/location.h"

#include <stdio.h>
#include <string.h>

static int ap_unknown_host(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			   bst_err *e)
{
	(void)e;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_unknown_host v = BST_UNKNOWN_HOST_DEFAULT;
	if (a->text[0] == '4')
		v = BST_UNKNOWN_HOST_421;
	else if (a->text[0] == 'c')
		v = BST_UNKNOWN_HOST_CLOSE;
	c->server->unknown_host = v;
	return 0;
}

static int ap_merge_slashes(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			    bst_err *e)
{
	(void)e;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bool v = true;
	(void)bst_parse_bool((bst_str){ a->text, (uint32_t)a->len }, &v); /* validated */
	c->common->merge_slashes = v;
	return 0;
}

static const char *const ev_unknown_host[] = { "default", "421", "close", NULL };

static int ap_regex_match_limit(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
				bst_err *e)
{
	(void)e;
	uint64_t v = 0;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	(void)bst_str_to_u64((bst_str){ a->text, (uint32_t)a->len }, &v); /* validated */
	c->global->regex_match_limit = (uint32_t)v;
	return 0;
}

static int ap_regex_depth_limit(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
				bst_err *e)
{
	(void)e;
	uint64_t v = 0;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	(void)bst_str_to_u64((bst_str){ a->text, (uint32_t)a->len }, &v);
	c->global->regex_depth_limit = (uint32_t)v;
	return 0;
}

static const bst_directive route_dirs[] = {
	{ .name = "merge_slashes", .contexts = BST_CTX_SERVER, .apply = ap_merge_slashes,
	  .default_value = "on",
	  .doc = "Collapse runs of '/' in the request path before routing and file lookup, so "
		 "//a///b is served as /a/b. With off they are kept as written, and an empty path "
		 "segment names nothing in a directory (a 404).",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_BOOL } } } },
	{ .name = "regex_match_limit", .contexts = BST_CTX_GLOBAL, .apply = ap_regex_match_limit,
	  .default_value = "100000",
	  .doc = "Most backtracking steps one regular-expression match may take (PCRE2's match "
		 "limit), for location, name and rewrite patterns. A match that reaches it is a "
		 "failure, not a non-match: the request is answered 500, so a pattern such as "
		 "(a+)+$ cannot hold a worker with a long URI. Raise it only for a pattern you "
		 "trust.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_INT, .min = 100, .max = 100000000 } } } },
	{ .name = "regex_depth_limit", .contexts = BST_CTX_GLOBAL, .apply = ap_regex_depth_limit,
	  .default_value = "1000",
	  .doc = "Deepest nesting of backtracking one regular-expression match may reach (PCRE2's "
		 "depth limit). Reaching it fails the match like regex_match_limit.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_INT, .min = 10, .max = 10000000 } } } },
	{ .name = "unknown_host", .contexts = BST_CTX_SERVER, .apply = ap_unknown_host,
	  .default_value = "default",
	  .doc = "What happens to a request whose Host matches no server name on the address it "
		 "arrived on. It is read on the default server of that address. default: the "
		 "default server answers. 421: answer 421 Misdirected Request and keep the "
		 "connection. close: close the connection without a response.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = ev_unknown_host } } } },
};
BST_DIRECTIVES(route_dirs);

/* Two servers cannot both be the default for one address. */
static int post_default_server(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	const bst_cfg_global *g = &cfg->global;
	for (size_t i = 0; i < g->nservers; i++)
		for (size_t j = 0; j < g->servers[i]->nlistens; j++) {
			const bst_cfg_listen *a = &g->servers[i]->listens[j];
			if (!a->default_server)
				continue;
			for (size_t k = i; k < g->nservers; k++)
				for (size_t m = k == i ? j + 1 : 0; m < g->servers[k]->nlistens; m++) {
					const bst_cfg_listen *b = &g->servers[k]->listens[m];
					if (!b->default_server || !bst_listen_same_socket(a, b))
						continue;
					char addr[BST_ADDR_STRLEN + 8];
					bst_addr_format(&a->addr.ip, addr, sizeof addr);
					bst_err_set(e, "two servers are the default_server for %s:%u",
						    addr, (unsigned)a->addr.port);
					bst_cfg_err_at(e, bst_cfg_src(c, &b->loc));
					return -1;
				}
		}
	return 0;
}
BST_CFG_POST(post_default_server);

/* Compiles the regexes and builds the location indexes (route/location.c). */
static int post_route_prepare(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	return bst_route_prepare(cfg, c, e);
}
BST_CFG_POST(post_route_prepare);

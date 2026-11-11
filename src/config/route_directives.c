/* Routing directives (Phase 5): which server answers a request (unknown_host, the default_server
 * flag of listen, checked here) and what a location does with it (added by the later tasks of
 * the phase in this file). */
#include "config/compile.h"
#include "config/errfmt.h"

#include <stdio.h>

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

static const char *const ev_unknown_host[] = { "default", "421", "close", NULL };

static const bst_directive route_dirs[] = {
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
					if (!b->default_server || b->addr.port != a->addr.port ||
					    !bst_ip_eq(&a->addr.ip, &b->addr.ip))
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

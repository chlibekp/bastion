/* The authentication directives shared by every mechanism, and Basic auth's (auth/basic.h).
 * Each inherits from global to server to location. */
#include "auth/basic.h"
#include "config/compile.h"
#include "config/values.h"

#include <stdlib.h>
#include <string.h>

#define UP1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }
#define GSL (BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION)
#define MS 1000

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

/* Users tables loaded by this compile, handed to the config's cleanups by the post hook. A
 * table of a compile that failed is handed to the next one that succeeds. */
static const bst_basic_users **g_pending;
static size_t g_npending, g_cap;

static int ap_auth_basic(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (bst_str_eq(as_str(a), BST_S("off"))) {
		c->common->auth.basic_realm = NULL;
		return 0;
	}
	if (memchr(a->text, '"', a->len) != NULL || memchr(a->text, '\\', a->len) != NULL) {
		bst_err_set(e, "auth_basic: the realm can not contain '\"' or '\\'");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	char *v = bst_cfg_strdup(c, a->text, a->len, e);
	if (v == NULL)
		return -1;
	c->common->auth.basic_realm = v;
	return 0;
}

static int ap_auth_basic_file(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
			      bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	char *path = bst_cfg_strdup(c, a->text, a->len, e);
	if (path == NULL)
		return -1;
	if (g_npending == g_cap) {
		size_t nc = g_cap ? g_cap * 2 : 8;
		const bst_basic_users **np = realloc(g_pending, nc * sizeof *np);
		if (np == NULL) {
			bst_err_set(e, "out of memory");
			return -1;
		}
		g_pending = np;
		g_cap = nc;
	}
	unsigned weak = 0;
	char why[160];
	const bst_basic_users *u = bst_basic_users_load(path, &weak, why, sizeof why);
	if (u == NULL) {
		bst_err_set(e, "auth_basic_file: can not load '%s': %s", path, why);
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	g_pending[g_npending++] = u;
	if (weak > 0)
		bst_cfg_warn(c, n, "auth_basic_file '%s': %u entr%s below m=19456 KiB, t=2 (weak)", path,
			     weak, weak == 1 ? "y is" : "ies are");
	c->common->auth.basic_users = u;
	return 0;
}

static int post_auth_users(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	(void)c;
	for (size_t i = 0; i < g_npending; i++)
		if (bst_config_on_free(cfg, bst_basic_users_free, (void *)g_pending[i], e) != 0)
			return -1;
	g_npending = 0;
	return 0;
}
BST_CFG_POST(post_auth_users);

static int ap_max_concurrent(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	int64_t v = 0;
	(void)bst_parse_int(as_str(bst_dir_pos(d, n, 0)), 1, 100000, &v);
	c->common->auth.max_concurrent = (unsigned)v;
	return 0;
}

static int ap_cache_ttl(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint64_t us = 0;
	(void)bst_parse_duration_us(as_str(bst_dir_pos(d, n, 0)), &us);
	c->common->auth.cache_ttl_ms = us / MS;
	return 0;
}

static int ap_require(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->auth.require_all = bst_str_eq(as_str(bst_dir_pos(d, n, 0)), BST_S("all"));
	return 0;
}

static const char *const require_v[] = { "any", "all", NULL };

static const bst_directive auth_dirs[] = {
	{ .name = "auth_basic", .contexts = GSL, .apply = ap_auth_basic, .default_value = "off",
	  .doc = "HTTP Basic authentication with this realm, against auth_basic_file; off turns it "
		 "off here. A missing or wrong password gets 401 with WWW-Authenticate. $auth_user is "
		 "the user let in.",
	  UP1({ .kind = BST_T_STRING }) },
	{ .name = "auth_basic_file", .contexts = GSL, .apply = ap_auth_basic_file,
	  .doc = "The users of auth_basic: `user:$argon2id$v=19$m=..,t=..,p=..$salt$hash` lines, as "
		 "`bastion passwd user` prints them. Read by the master at load (a file that can not be "
		 "read or parsed fails the load) and kept out of core dumps. Entries weaker than "
		 "m=19456 KiB, t=2 draw a warning.",
	  UP1({ .kind = BST_T_PATH }) },
	{ .name = "auth_max_concurrent", .contexts = GSL, .apply = ap_max_concurrent,
	  .default_value = "16",
	  .doc = "Password hashes one worker runs at once (they run on the aio pool, never on the "
		 "event loop). Past it a request needing one gets 503 with Retry-After: 1, so a "
		 "password flood can not take the worker down.",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 100000 }) },
	{ .name = "auth_cache_ttl", .contexts = GSL, .apply = ap_cache_ttl, .default_value = "60s",
	  .doc = "How long a verified credential is remembered per worker, keyed by an HMAC with a "
		 "random per-worker key (never the plaintext); 0s hashes every request.",
	  UP1({ .kind = BST_T_DURATION, .min = 0, .max = 86400ll * 1000000 }) },
	{ .name = "auth_require", .contexts = GSL, .apply = ap_require, .default_value = "any",
	  .doc = "How the mechanisms configured here combine (auth_mtls, auth_jwt, auth_basic, "
		 "auth_forward, checked in that order): any lets in the first that passes, all needs "
		 "every one.",
	  UP1({ .kind = BST_T_ENUM, .enum_values = require_v }) },
};
BST_DIRECTIVES(auth_dirs);

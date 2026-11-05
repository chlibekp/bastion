/* libFuzzer harness for the whole config pipeline: parse, validate and compile against the
 * real core schema plus a fixture table (singleton block with a defaulted child, exclusive
 * pair with a default, list directives), then print the effective configuration (-T) and
 * check the fixed point: the printed text must parse, validate and compile again to an
 * identical result, and printing that result again must give the same bytes.
 *
 * Allowed failures: parse, validate or compile errors (they must carry a message), and a
 * printer refusal (an argument that cannot be spelled so it re-reads the same, or one with
 * a control byte). Everything else that differs is a bug. Includes are disabled so no input
 * can read host files; environment expansion stays on (the printed text has the values
 * inserted, so the second parse does not depend on the environment). */
#include "config/compile.h"
#include "config/dump.h"
#include "config/parser.h"
#include "config/schema.h"
#include "core/arena.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Fixture: state is recorded here, since the compile result has no field for it ---- */

static int g_threads, g_lb_applies;
static const char *g_lb;

static int ap_io(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e;
	return 0;
}

static int ap_threads(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)e;
	g_threads = atoi(bst_dir_pos(d, n, 0)->text);
	return 0;
}

static int ap_lb(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)n, (void)e;
	g_lb = d->subname;
	g_lb_applies++;
	return 0;
}

static int ap_tag(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	char *cp = bst_cfg_strdup(c, a->text, a->len, e);
	return cp ? bst_cfg_list_append(c, &c->common->tags, cp, e) : -1;
}

static int ap_xtag(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	char *cp = bst_cfg_strdup(c, a->text, a->len, e);
	return cp ? bst_cfg_list_extend(c, &c->common->tags, cp, e) : -1;
}

static int ap_dtag(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	char *cp = bst_cfg_strdup(c, a->text, a->len, e);
	return cp ? bst_cfg_list_append(c, &c->common->dtags, cp, e) : -1;
}

#define SVLOC (BST_CTX_SERVER | BST_CTX_LOCATION)
#define STR1 .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } }
static const bst_directive fx_dirs[] = {
	{ .name = "fx_io", .contexts = BST_CTX_GLOBAL, .apply = ap_io, .singleton = true,
	  .child_ctx = BST_CTX_IO, .doc = "fixture singleton block",
	  .args = { .block = BST_BLOCK_REQUIRED } },
	{ .name = "fx_threads", .contexts = BST_CTX_IO, .apply = ap_threads, .default_value = "4",
	  .doc = "fixture default inside the singleton",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_INT, .min = 1, .max = 64 } } } },
	{ .name = "fx_lb", .subname = "round_robin", .contexts = BST_CTX_SERVER, .apply = ap_lb,
	  .default_value = "", .subname_exclusive = true, .doc = "fixture exclusive default" },
	{ .name = "fx_lb", .subname = "least_conn", .contexts = BST_CTX_SERVER, .apply = ap_lb,
	  .subname_exclusive = true, .doc = "fixture exclusive alternative" },
	{ .name = "fx_tag", .contexts = BST_CTX_GLOBAL | SVLOC, .apply = ap_tag,
	  .repeatable = true, .doc = "fixture list: append", STR1 },
	{ .name = "fx_xtag", .contexts = BST_CTX_GLOBAL | SVLOC, .apply = ap_xtag,
	  .repeatable = true, .doc = "fixture list: extend", STR1 },
	{ .name = "fx_dtag", .contexts = SVLOC, .apply = ap_dtag, .repeatable = true,
	  .default_value = "d0", .doc = "fixture list with a default", STR1 },
};
static const bst_dirtab fx_tab = { fx_dirs, sizeof fx_dirs / sizeof fx_dirs[0] };

static bst_schema *SC;

/* ---- A canonical text of a compile result, to compare two of them ---- */

typedef struct out {
	char *p;
	size_t len, cap;
} out;

static void put(out *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void put(out *o, const char *fmt, ...)
{
	char tmp[512];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
	va_end(ap);
	if (n < 0)
		abort();
	size_t l = (size_t)n < sizeof tmp ? (size_t)n : sizeof tmp - 1;
	if (o->len + l + 1 > o->cap) {
		o->cap = (o->len + l + 1) * 2;
		o->p = realloc(o->p, o->cap);
		if (!o->p)
			abort();
	}
	memcpy(o->p + o->len, tmp, l);
	o->len += l;
	o->p[o->len] = 0;
}

static void put_list(out *o, const char *tag, const bst_cfg_list *l)
{
	put(o, " %s[", tag);
	for (size_t i = 0; i < l->n; i++)
		put(o, "%s%s", i ? "," : "", (const char *)l->items[i]);
	put(o, "]");
}

static void put_loc(out *o, const bst_cfg_location *l, int depth)
{
	put(o, "%*sloc mod=%d pat=%s cmbs=%llu", depth * 2, "", (int)l->mod, l->pattern,
	    (unsigned long long)l->common.client_max_body_size);
	put_list(o, "tags", &l->common.tags);
	put_list(o, "dtags", &l->common.dtags);
	put(o, "\n");
	for (size_t i = 0; i < l->nchildren; i++)
		put_loc(o, l->children[i], depth + 1);
}

static char *canon(const bst_config *c)
{
	out o = { 0 };
	const bst_cfg_global *g = &c->global;
	put(&o, "user=%s workers=%d/%d pid=%s elog=%s/%s cmbs=%llu threads=%d lb=%s/%d",
	    g->user ? g->user : "-", g->workers_auto, g->workers, g->pid ? g->pid : "-",
	    g->error_log ? g->error_log : "-", g->error_log_level ? g->error_log_level : "-",
	    (unsigned long long)g->common.client_max_body_size, g_threads, g_lb ? g_lb : "-",
	    g_lb_applies);
	put_list(&o, "tags", &g->common.tags);
	put(&o, "\n");
	for (size_t i = 0; i < g->nservers; i++) {
		const bst_cfg_server *s = g->servers[i];
		put(&o, "server cmbs=%llu names=", (unsigned long long)s->common.client_max_body_size);
		for (size_t k = 0; k < s->nnames; k++)
			put(&o, "%s%s", k ? "," : "", s->names[k]);
		put(&o, " listens=");
		for (size_t k = 0; k < s->nlistens; k++)
			put(&o, "%s%d/%u:%u", k ? "," : "", (int)s->listens[k].addr.ip.family,
			    (unsigned)s->listens[k].addr.ip.b[15], (unsigned)s->listens[k].addr.port);
		put_list(&o, "tags", &s->common.tags);
		put_list(&o, "dtags", &s->common.dtags);
		put(&o, "\n");
		for (size_t k = 0; k < s->nlocations; k++)
			put_loc(&o, s->locations[k], 1);
	}
	return o.p;
}

/* ---- The pipeline ---- */

static bst_config *compile_text(const char *text, size_t len, bst_arena **keep, bst_err *e,
				char **canon_out)
{
	bst_arena *a = bst_arena_new(1 << 16);
	if (!a)
		abort();
	bst_cfg_opts o = { .no_include = 1 };
	bst_ast *ast = bst_cfg_parse_string(text, len, "fuzz", &o, a, e);
	bst_config *cfg = NULL;
	if (ast) {
		g_threads = g_lb_applies = 0;
		g_lb = NULL;
		cfg = bst_cfg_compile_with(SC, ast, e);
		if (cfg)
			*canon_out = canon(cfg);
	}
	if (!cfg && (e->msg[0] == 0 || e->line < 0 || e->col < 0))
		abort(); /* every failure carries a message and a sane position */
	*keep = a;
	return cfg;
}

static char *dump_text(const bst_ast *ast, size_t *len, bst_err *e)
{
	char *buf = NULL;
	FILE *f = open_memstream(&buf, len);
	if (!f)
		abort();
	int rc = bst_cfg_dump(SC, ast, f, e);
	fclose(f);
	if (rc != 0) {
		free(buf);
		return NULL;
	}
	return buf;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc, (void)argv;
	bst_err e;
	SC = bst_schema_build((const bst_dirtab *const[]){ bst_cfg_core_dirtab(), &fx_tab }, 2, &e);
	if (!SC)
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	char *copy = malloc(size ? size : 1);
	if (!copy)
		abort();
	memcpy(copy, d, size);
	bst_err e;
	bst_arena *a1 = NULL, *a2 = NULL;
	char *c1 = NULL, *c2 = NULL, *d1 = NULL, *d2 = NULL;
	bst_config *cfg1 = compile_text(copy, size, &a1, &e, &c1);
	if (cfg1 != NULL) {
		/* Re-parse the original to hand the printer its AST (compile_text kept the arena). */
		bst_cfg_opts o = { .no_include = 1 };
		bst_arena *pa = bst_arena_new(1 << 16);
		if (!pa)
			abort();
		bst_ast *ast = bst_cfg_parse_string(copy, size, "fuzz", &o, pa, &e);
		if (!ast)
			abort(); /* it parsed a moment ago */
		size_t n1 = 0;
		d1 = dump_text(ast, &n1, &e);
		if (d1 != NULL) {
			bst_config *cfg2 = compile_text(d1, n1, &a2, &e, &c2);
			if (cfg2 == NULL) /* the printed config is the same config: it must compile */
				abort();
			if (strcmp(c1, c2) != 0)
				abort(); /* identical compile result */
			bst_arena *pb = bst_arena_new(1 << 16);
			bst_ast *ast2 = pb ? bst_cfg_parse_string(d1, n1, "fuzz", &o, pb, &e) : NULL;
			if (!ast2)
				abort();
			size_t n2 = 0;
			d2 = dump_text(ast2, &n2, &e);
			if (d2 == NULL || n1 != n2 || memcmp(d1, d2, n1) != 0)
				abort(); /* the fixed point */
			bst_arena_free(pb);
			bst_config_free(cfg2);
		} else if (e.msg[0] == 0) {
			abort(); /* a refusal says why */
		}
		bst_arena_free(pa);
		bst_config_free(cfg1);
	}
	bst_arena_free(a1);
	bst_arena_free(a2);
	free(c1);
	free(c2);
	free(d1);
	free(d2);
	free(copy);
	return 0;
}

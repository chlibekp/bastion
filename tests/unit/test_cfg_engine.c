/* The engine contract that later phases build on: singleton blocks and their defaults,
 * list replace/append/extend semantics, post-apply hooks (resolution and positioned
 * errors under ASan), load-time warnings, and exclusive-pair defaults. The fixture
 * directives register in the real registry of this test binary only (BST_DIRECTIVES works
 * from any translation unit), so the CLI runs against core + fixture exactly as a later
 * phase's directives would. */
#include "config/cli.h"
#include "config/compile.h"
#include "config/dump.h"
#include "config/parser.h"
#include "config/schema.h"
#include "core/arena.h"
#include "tap.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- Fixture state (one compile at a time) ---- */

static int g_io_applied, g_threads, g_lb_applied, g_dtag_applied;
static const char *g_lb;

static void reset(void)
{
	g_io_applied = g_threads = g_lb_applied = g_dtag_applied = 0;
	g_lb = NULL;
}

static int ap_io(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e;
	g_io_applied++;
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
	g_lb_applied++;
	return 0;
}

/* tags: append replaces the parent's list on the first statement of a scope, extend keeps it. */
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

/* A list that has a default: its own field, so it does not mix with fx_tag's. */
static int ap_dtag(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	char *cp = bst_cfg_strdup(c, a->text, a->len, e);
	g_dtag_applied++;
	return cp ? bst_cfg_list_append(c, &c->common->dtags, cp, e) : -1;
}

/* want NAME: recorded now, resolved to a server pointer by a post hook. */
#define MAXW 8
static struct { const char *name; bst_cfg_loc loc; } g_wants[MAXW];
static const bst_cfg_server *g_resolved[MAXW];
static size_t g_nwants;
static char g_order[8];
static bool g_hook_warn;

static int ap_want(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (g_nwants == MAXW)
		return 0;
	g_wants[g_nwants].name = bst_cfg_strdup(c, a->text, a->len, e);
	if (g_wants[g_nwants].name == NULL ||
	    bst_cfg_loc_of(c, n, &g_wants[g_nwants].loc, e) != 0)
		return -1;
	g_nwants++;
	return 0;
}

/* Defined (so linked) before post_a_resolve: address order is "ba", name order "ab". */
static int post_b_order(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	(void)cfg, (void)e;
	strcat(g_order, "b");
	if (g_hook_warn && g_nwants > 0)
		bst_cfg_warn_at(c, bst_cfg_src(c, &g_wants[0].loc), "want \"%s\" resolved",
				g_wants[0].name);
	return 0;
}
BST_CFG_POST(post_b_order);

static int post_a_resolve(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	strcat(g_order, "a");
	for (size_t i = 0; i < g_nwants; i++) {
		g_resolved[i] = NULL;
		for (size_t k = 0; k < cfg->global.nservers; k++) {
			const bst_cfg_server *s = cfg->global.servers[k];
			if (s->nnames > 0 && strcmp(s->names[0], g_wants[i].name) == 0)
				g_resolved[i] = s;
		}
		if (g_resolved[i] == NULL) {
			bst_err_set(e, "no server named \"%s\"", g_wants[i].name);
			bst_cfg_err_at(e, bst_cfg_src(c, &g_wants[i].loc));
			return -1;
		}
	}
	return 0;
}
BST_CFG_POST(post_a_resolve);


static int ap_warn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bst_cfg_warn(c, n, "value \"%s\" is risky \033[1m", bst_dir_pos(d, n, 0)->text);
	return 0;
}

#define STR1 .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } }
#define SVLOC (BST_CTX_SERVER | BST_CTX_LOCATION)
static int ap_flag(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e;
	return 0;
}
static const char *const ev_flag[] = { "tls", "http2", NULL };

static const bst_directive fx_dirs[] = {
	{ .name = "fx_flag", .contexts = BST_CTX_GLOBAL, .apply = ap_flag, .repeatable = true,
	  .doc = "fixture flag: the pattern for listen flags (BST_T_ENUM, not keywords)",
	  .args = { .min_args = 1, .max_args = 2,
		    .pos = { { .kind = BST_T_INT, .min = 1, .max = 9 },
			     { .kind = BST_T_ENUM, .enum_values = ev_flag } } } },
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
	{ .name = "fx_want", .contexts = BST_CTX_GLOBAL, .apply = ap_want, .repeatable = true,
	  .doc = "fixture reference resolved by a hook", STR1 },
	{ .name = "fx_warn", .contexts = BST_CTX_GLOBAL, .apply = ap_warn, .repeatable = true,
	  .doc = "fixture warning", STR1 },
};
BST_DIRECTIVES(fx_dirs);

/* The singleton fixture is NOT registered: it lives in a private schema (core + this
 * table), so it can never collide with a real context's directives (io, acme, ...). */
static const bst_directive fx_single[] = {
	{ .name = "fx_io", .contexts = BST_CTX_GLOBAL, .apply = ap_io, .singleton = true,
	  .child_ctx = BST_CTX_IO, .doc = "fixture singleton block",
	  .args = { .block = BST_BLOCK_REQUIRED } },
	{ .name = "fx_threads", .contexts = BST_CTX_IO, .apply = ap_threads, .default_value = "4",
	  .doc = "fixture default inside the singleton",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_INT, .min = 1, .max = 64 } } } },
};
static bst_err E; /* defined again below (tentative) */
static const bst_dirtab fx_single_tab = { fx_single, sizeof fx_single / sizeof fx_single[0] };
static const bst_schema *single_schema(void)
{
	static bst_schema *sc;
	if (sc == NULL) {
		const bst_dirtab *tabs[] = { bst_cfg_core_dirtab(), &fx_single_tab };
		sc = bst_schema_build(tabs, 2, &E);
	}
	return sc;
}

/* ---- Helpers ---- */

static bst_err E;
static bst_arena *LAST;

/* The AST stays alive until the next call, so E.file (which points into it) is readable. */
static bst_ast *LASTAST;
static bst_config *compile(const char *text)
{
	bst_arena_free(LAST);
	LAST = bst_arena_new(1 << 16);
	memset(&E, 0, sizeof E);
	reset();
	g_nwants = 0;
	g_order[0] = 0;
	LASTAST = bst_cfg_parse_string(text, strlen(text), "t.conf", NULL, LAST, &E);
	return LASTAST ? bst_cfg_compile(LASTAST, &E) : NULL;
}

static bst_config *compile_single(const char *text)
{
	bst_arena_free(LAST);
	LAST = bst_arena_new(1 << 16);
	memset(&E, 0, sizeof E);
	reset();
	g_nwants = 0;
	g_order[0] = 0;
	LASTAST = bst_cfg_parse_string(text, strlen(text), "t.conf", NULL, LAST, &E);
	return LASTAST ? bst_cfg_compile_with(single_schema(), LASTAST, &E) : NULL;
}

static char *dump_with(const bst_schema *sc);
static char *dump_of(void)
{
	return dump_with(bst_schema_registry(&E));
}
static char *dump_single_of(void)
{
	return dump_with(single_schema());
}
static char *dump_with(const bst_schema *sc)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *f = open_memstream(&buf, &len);
	int rc = bst_cfg_dump(sc, LASTAST, f, &E);
	fclose(f);
	if (rc != 0) {
		free(buf);
		return NULL;
	}
	return buf;
}

static bool tags_are(const bst_cfg_list *l, const char *const *want, size_t n)
{
	if (l->n != n)
		return false;
	for (size_t i = 0; i < n; i++)
		if (strcmp(l->items[i], want[i]) != 0)
			return false;
	return true;
}
#define TAGS(l, ...)                                                                    \
	tags_are(&(l), (const char *const[]){ __VA_ARGS__ },                            \
		 sizeof((const char *const[]){ __VA_ARGS__ }) / sizeof(char *))

/* ---- 1. Singleton blocks ---- */

TEST(singleton_absent_block_gets_defaults)
{
	bst_config *c = compile_single("server { listen 80; }");
	ASSERT(c != NULL);
	ASSERT_EQ(g_io_applied, 1); /* synthesised */
	ASSERT_EQ(g_threads, 4);
	bst_config_free(c);
}

TEST(singleton_empty_and_explicit_block)
{
	bst_config *c = compile_single("fx_io { }");
	ASSERT(c != NULL);
	ASSERT_EQ(g_io_applied, 1);
	ASSERT_EQ(g_threads, 4);
	bst_config_free(c);
	c = compile_single("fx_io { fx_threads 9; }");
	ASSERT(c != NULL);
	ASSERT_EQ(g_io_applied, 1);
	ASSERT_EQ(g_threads, 9);
	bst_config_free(c);
}

TEST(singleton_duplicate_is_an_error)
{
	ASSERT(compile_single("fx_io { }\nfx_io { fx_threads 2; }") == NULL);
	ASSERT(strstr(E.msg, "duplicate \"fx_io\"") != NULL);
	ASSERT_EQ(E.line, 2);
}

TEST(singleton_dump_prints_block_with_defaults)
{
	bst_config *c = compile_single("workers 2;");
	ASSERT(c != NULL);
	char *d = dump_single_of();
	ASSERT(d != NULL);
	ASSERT(strstr(d, "fx_io {\n    fx_threads 4;\n}\n") != NULL);
	bst_config_free(c);
	free(d);
	/* An explicit value is not shadowed by a printed default. */
	c = compile_single("fx_io { fx_threads 7; }");
	d = dump_single_of();
	ASSERT(d != NULL && strstr(d, "fx_threads 7;") != NULL && strstr(d, "fx_threads 4;") == NULL);
	bst_config_free(c);
	free(d);
}

TEST(singleton_integrity)
{
	static const bst_directive bad_rep[] = {
		{ .name = "x", .contexts = BST_CTX_GLOBAL, .doc = "d", .apply = ap_io,
		  .singleton = true, .repeatable = true, .child_ctx = BST_CTX_IO,
		  .args = { .block = BST_BLOCK_REQUIRED } },
	};
	static const bst_directive bad_noblock[] = {
		{ .name = "x", .contexts = BST_CTX_GLOBAL, .doc = "d", .apply = ap_io,
		  .singleton = true },
	};
	bst_dirtab t1 = { bad_rep, 1 }, t2 = { bad_noblock, 1 };
	ASSERT(bst_schema_build((const bst_dirtab *const[]){ &t1 }, 1, &E) == NULL);
	ASSERT(bst_schema_build((const bst_dirtab *const[]){ &t2 }, 1, &E) == NULL);
}

/* ---- 2. Lists ---- */

TEST(list_first_statement_replaces_parent)
{
	bst_config *c = compile("fx_tag g1; server { listen 80; fx_tag s1; location /a { } }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT(TAGS(c->global.common.tags, "g1"));
	ASSERT(TAGS(s->common.tags, "s1"));
	ASSERT(TAGS(s->locations[0]->common.tags, "s1")); /* a plain child inherits */
	bst_config_free(c);
}

TEST(list_append_within_scope_and_siblings_isolated)
{
	bst_config *c = compile("fx_tag g1; server { listen 80; fx_tag s1; fx_tag s2;\n"
				"  location /a { fx_tag a1; fx_tag a2; location /a/x { fx_tag x1; } }\n"
				"  location /b { fx_tag b1; } location /c { } }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT(TAGS(s->common.tags, "s1", "s2"));
	ASSERT(TAGS(s->locations[0]->common.tags, "a1", "a2"));
	ASSERT(TAGS(s->locations[0]->children[0]->common.tags, "x1"));
	ASSERT(TAGS(s->locations[1]->common.tags, "b1"));
	ASSERT(TAGS(s->locations[2]->common.tags, "s1", "s2"));
	ASSERT(TAGS(c->global.common.tags, "g1"));
	bst_config_free(c);
}

TEST(list_extend_keeps_parent_and_adds)
{
	bst_config *c = compile("fx_tag g1; server { listen 80; fx_xtag s1; fx_xtag s2;\n"
				"  location /a { fx_xtag a1; } location /b { } }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT(TAGS(s->common.tags, "g1", "s1", "s2"));
	ASSERT(TAGS(s->locations[0]->common.tags, "g1", "s1", "s2", "a1"));
	ASSERT(TAGS(s->locations[1]->common.tags, "g1", "s1", "s2"));
	ASSERT(TAGS(c->global.common.tags, "g1"));
	bst_config_free(c);
}

TEST(list_default_is_replaced_by_user_values)
{
	bst_config *c = compile("server { listen 80; location /a { fx_dtag x; fx_dtag y; }\n"
				"  location /b { } }\n"
				"server { listen 81; fx_dtag u; location /c { } }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0], *s2 = c->global.servers[1];
	ASSERT(TAGS(s->common.dtags, "d0"));
	ASSERT(TAGS(s->locations[0]->common.dtags, "x", "y"));
	ASSERT(TAGS(s->locations[1]->common.dtags, "d0"));
	ASSERT(TAGS(s2->common.dtags, "u")); /* not d0,u: the default is skipped where set */
	ASSERT(TAGS(s2->locations[0]->common.dtags, "u"));
	bst_config_free(c);
}

/* ---- 3. Post-apply hooks ---- */

TEST(post_hook_resolves_name_to_pointer)
{
	bst_config *c = compile("server { listen 1; name a.com; } server { listen 2; name b.com; }\n"
				"fx_want b.com; fx_want a.com;");
	ASSERT(c != NULL);
	ASSERT_EQ(g_nwants, 2);
	ASSERT(g_resolved[0] == c->global.servers[1]);
	ASSERT(g_resolved[1] == c->global.servers[0]);
	bst_config_free(c);
}

TEST(post_hooks_run_in_name_order)
{
	bst_config *c = compile("server { listen 1; }");
	ASSERT(c != NULL);
	ASSERT_STR(g_order, "ab");
	bst_config_free(c);
}

TEST(flag_typo_errors_with_a_suggestion)
{
	bst_config *ok = compile("fx_flag 1 tls;");
	ASSERT(ok != NULL);
	bst_config_free(ok);
	ASSERT(compile("fx_flag 1 tsl;") == NULL);
	ASSERT(strstr(E.msg, "expected one of") != NULL);
	ASSERT(strstr(E.msg, "did you mean \"tls\"") != NULL);
	ASSERT(compile("fx_flag 1 zzzzzz;") == NULL);
	ASSERT(strstr(E.msg, "did you mean") == NULL);
}

TEST(post_hook_error_carries_ast_position)
{
	ASSERT(compile("server { listen 1; name a.com; }\nfx_want nope.com;") == NULL);
	ASSERT(strstr(E.msg, "no server named \"nope.com\"") != NULL);
	ASSERT_STR(E.file, "t.conf"); /* the AST's copy: still alive here */
	ASSERT_EQ(E.line, 2);
	ASSERT_EQ(E.col, 1);
}

/* ---- 4. Warnings, and the CLI under ASan ---- */

static char *slurp(int fd)
{
	char *b = calloc(1, 8192);
	lseek(fd, 0, SEEK_SET);
	ssize_t n = read(fd, b, 8191);
	if (n < 0)
		n = 0;
	b[n] = 0;
	return b;
}

/* Runs the CLI in-process with stdout and stderr captured. */
static int capture_cli(int argc, char **argv, char **out, char **err)
{
	FILE *fo = tmpfile(), *fe = tmpfile();
	fflush(stdout);
	fflush(stderr);
	int so = dup(1), se = dup(2);
	dup2(fileno(fo), 1);
	dup2(fileno(fe), 2);
	int rc = bst_cli_main(argc, argv);
	fflush(stdout);
	fflush(stderr);
	dup2(so, 1);
	dup2(se, 2);
	close(so);
	close(se);
	*out = slurp(fileno(fo));
	*err = slurp(fileno(fe));
	fclose(fo);
	fclose(fe);
	return rc;
}

/* Writes conf_text to a temp file and runs `bastion -c file flag`; fills out, err and path. */
static int run_cli(const char *conf_text, const char *flag, char **out, char **err, char *path)
{
	reset();
	g_nwants = 0;
	g_order[0] = 0;
	strcpy(path, "/tmp/bst_engine_XXXXXX");
	int cfd = mkstemp(path);
	if (cfd < 0 || write(cfd, conf_text, strlen(conf_text)) < 0)
		abort();
	close(cfd);
	char *argv[] = { "bastion", "-c", path, (char *)flag, NULL };
	int rc = capture_cli(4, argv, out, err);
	unlink(path);
	return rc;
}

static size_t count_of(const char *hay, const char *needle)
{
	size_t n = 0;
	for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle))
		n++;
	return n;
}

TEST(missing_config_path_is_printed_once)
{
	char *out, *err;
	char *argv[] = { "bastion", "-c", "/nonexistent/dir/nope.conf", "-t", NULL };
	ASSERT_EQ(capture_cli(4, argv, &out, &err), 1);
	ASSERT_STR(err, "/nonexistent/dir/nope.conf: cannot open: No such file or directory\n");
	free(out);
	free(err);
	if (access(BST_DEFAULT_CONFIG, R_OK) != 0) { /* the default path, when it does not exist */
		char *argv2[] = { "bastion", "-t", NULL };
		ASSERT_EQ(capture_cli(2, argv2, &out, &err), 1);
		ASSERT_EQ(count_of(err, BST_DEFAULT_CONFIG), 1);
		ASSERT(strstr(err, "cannot read the default configuration (use -c file)") != NULL);
		free(out);
		free(err);
	}
}

TEST(warning_is_collected_with_position)
{
	bst_config *c = compile("server { listen 1; }\nfx_warn abc;");
	ASSERT(c != NULL);
	size_t n = 0;
	const bst_cfg_warning *w = bst_config_warnings(c, &n);
	ASSERT_EQ(n, 1);
	ASSERT_STR(w[0].file, "t.conf");
	ASSERT_EQ(w[0].line, 2);
	ASSERT_EQ(w[0].col, 1);
	ASSERT(strstr(w[0].msg, "value \"abc\" is risky") != NULL);
	/* The positions are copies: the AST may go away. */
	bst_arena_free(LAST);
	LAST = NULL;
	ASSERT_STR(w[0].file, "t.conf");
	bst_config_free(c);
	c = compile("server { listen 1; }");
	ASSERT(c != NULL);
	bst_config_warnings(c, &n);
	ASSERT_EQ(n, 0);
	bst_config_free(c);
}

TEST(warning_from_a_post_hook)
{
	g_hook_warn = true;
	bst_config *c = compile("server { listen 1; name a.com; }\nfx_want a.com;");
	g_hook_warn = false;
	ASSERT(c != NULL);
	size_t n = 0;
	const bst_cfg_warning *w = bst_config_warnings(c, &n);
	ASSERT_EQ(n, 1);
	ASSERT_EQ(w[0].line, 2);
	ASSERT(strstr(w[0].msg, "want \"a.com\" resolved") != NULL);
	bst_config_free(c);
}

TEST(t_warning_keeps_exit_zero)
{
	char *out, *err, path[64];
	int rc = run_cli("server { listen 1; }\nfx_warn abc;\n", "-t", &out, &err, path);
	ASSERT_EQ(rc, 0);
	/* -t also reports the I/O backend (it probes as a worker would): see test_backend.py */
	ASSERT(strncmp(out, "configuration ok\nio backend: ", 29) == 0);
	char want[200];
	snprintf(want, sizeof want, "%s:2:1: warning: value \"abc\" is risky \\x1b[1m\n", path);
	ASSERT_STR(err, want); /* positioned, escaped, one line */
	free(out);
	free(err);
	rc = run_cli("server { listen 1; }\nfx_warn abc;\n", "-T", &out, &err, path);
	ASSERT_EQ(rc, 0);
	ASSERT(strstr(err, ":2:1: warning: value") != NULL);
	ASSERT(strstr(out, "fx_warn abc;") != NULL);
	free(out);
	free(err);
}

TEST(cli_hook_error_prints_position_under_asan)
{
	char *out, *err, path[64];
	int rc = run_cli("server { listen 1; name a.com; }\nfx_want nope.com;\n", "-t", &out, &err,
			 path);
	ASSERT_EQ(rc, 1);
	char want[200];
	snprintf(want, sizeof want, "%s:2:1: no server named \"nope.com\"\n", path);
	ASSERT_STR(err, want);
	ASSERT_STR(out, "");
	free(out);
	free(err);
}

/* ---- 6. Exclusive pairs ---- */

TEST(exclusive_default_skipped_when_any_member_set)
{
	bst_config *c = compile("server { listen 1; }");
	ASSERT(c != NULL);
	ASSERT_STR(g_lb, "round_robin");
	ASSERT_EQ(g_lb_applied, 1);
	bst_config_free(c);
	c = compile("server { listen 1; fx_lb least_conn; }");
	ASSERT(c != NULL);
	ASSERT_STR(g_lb, "least_conn");
	ASSERT_EQ(g_lb_applied, 1); /* the default did not run first */
	bst_config_free(c);
}

TEST(exclusive_dump_is_a_fixed_point)
{
	bst_config *c = compile("server { listen 1; fx_lb least_conn; }");
	ASSERT(c != NULL);
	char *d1 = dump_of();
	ASSERT(d1 != NULL);
	ASSERT(strstr(d1, "least_conn") != NULL && strstr(d1, "round_robin") == NULL);
	bst_config_free(c);
	/* Re-parse, compile and dump again: identical. */
	c = compile(d1);
	ASSERT(c != NULL);
	char *d2 = dump_of();
	ASSERT(d2 != NULL && strcmp(d1, d2) == 0);
	bst_config_free(c);
	/* With nothing set, the default prints once and the result is also a fixed point. */
	c = compile("server { listen 1; }");
	free(d1);
	d1 = dump_of();
	ASSERT(d1 != NULL && strstr(d1, "fx_lb round_robin;") != NULL);
	bst_config_free(c);
	c = compile(d1);
	ASSERT(c != NULL);
	free(d2);
	d2 = dump_of();
	ASSERT(d2 != NULL && strcmp(d1, d2) == 0);
	bst_config_free(c);
	free(d1);
	free(d2);
}

TAP_MAIN()

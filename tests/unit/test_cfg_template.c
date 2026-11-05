#include "config/parser.h"
#include "config/schema.h"
#include "config/template.h"
#include "core/arena.h"
#include "tap.h"

#include <string.h>

/* Fixture ctx: the opaque bst_var_ctx is defined here, never by the module. */
struct bst_var_ctx {
	bst_arena *a;
	const char *host, *argy, *cap1, *hdr;
	int calls;
};

static bst_str cs(const char *s)
{
	return s ? (bst_str){ s, (uint32_t)strlen(s) } : (bst_str){ "", 0 };
}
static bst_str v_host(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	((struct bst_var_ctx *)(uintptr_t)c)->calls++;
	return cs(c->host);
}
static bst_str v_arg(const bst_var_ctx *c, bst_str sfx)
{
	return bst_str_eq(sfx, BST_S("y")) ? cs(c->argy) : (bst_str){ "", 0 };
}
static bst_str v_http(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return cs(c->hdr);
}
static bst_str v_cap1(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return cs(c->cap1);
}
static bst_str v_uri(const bst_var_ctx *c, bst_str sfx)
{
	(void)c, (void)sfx;
	return BST_S("/p");
}
static bst_str v_nul(const bst_var_ctx *c, bst_str sfx)
{
	(void)c, (void)sfx;
	return (bst_str){ "x\0y", 3 };
}
static bst_str v_huge(const bst_var_ctx *c, bst_str sfx)
{
	(void)c, (void)sfx;
	return (bst_str){ "x", UINT32_MAX - 1 }; /* never dereferenced: the total is refused */
}

static bst_var_reg *mkreg(void)
{
	bst_err e;
	bst_var_reg *r = bst_var_reg_new();
	if (!r || bst_var_register(r, "host", v_host, &e) || bst_var_register(r, "uri", v_uri, &e) ||
	    bst_var_register(r, "huge", v_huge, &e) || bst_var_register(r, "nul", v_nul, &e) || bst_var_register(r, "1", v_cap1, &e) ||
	    bst_var_register_prefix(r, "arg_", v_arg, &e) ||
	    bst_var_register_prefix(r, "http_", v_http, &e))
		abort();
	return r;
}

static struct bst_var_ctx mkctx(bst_arena *a)
{
	return (struct bst_var_ctx){ .a = a, .host = "ex.com", .argy = "Y", .cap1 = "C1",
				     .hdr = "H" };
}

static bst_tpl *cmp(const bst_var_reg *r, const char *s, bst_arena *a, bst_err *e)
{
	return bst_tpl_compile_with(r, cs(s), NULL, false, a, e);
}

static bool eq(bst_str s, const char *lit)
{
	return s.p != NULL && s.len == strlen(lit) && memcmp(s.p, lit, s.len) == 0;
}

TEST(literal_only)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	bst_tpl *t = cmp(r, "/static/x.css", a, &e);
	ASSERT(t != NULL);
	ASSERT(bst_tpl_is_literal(t));
	/* NULL arena: any allocation attempt would fail, so success proves none happened. */
	bst_str s = bst_tpl_eval(t, NULL, NULL);
	ASSERT(eq(s, "/static/x.css"));
	bst_tpl *z = cmp(r, "", a, &e);
	ASSERT(z != NULL);
	s = bst_tpl_eval(z, NULL, NULL);
	ASSERT(!bst_str_failed(s) && s.len == 0);
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(mixed)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	struct bst_var_ctx c = mkctx(a);
	bst_tpl *t = cmp(r, "/new/$1?x=$arg_y", a, &e);
	ASSERT(t != NULL);
	ASSERT(eq(bst_tpl_eval(t, &c, a), "/new/C1?x=Y"));
	/* the variable function runs exactly once per eval */
	t = cmp(r, "$host$host", a, &e);
	c.calls = 0;
	ASSERT(eq(bst_tpl_eval(t, &c, a), "ex.comex.com"));
	ASSERT_EQ(c.calls, 2);
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(single_var_no_copy)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	struct bst_var_ctx c = mkctx(a);
	bst_tpl *t = cmp(r, "$host", a, &e);
	ASSERT(t != NULL);
	bst_str s = bst_tpl_eval(t, &c, NULL); /* no arena needed */
	ASSERT(eq(s, "ex.com"));
	ASSERT(s.p == c.host);
	c.host = NULL; /* missing value: empty but not a failure */
	s = bst_tpl_eval(t, &c, NULL);
	ASSERT(!bst_str_failed(s) && s.len == 0);
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(unknown_var)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	ASSERT(cmp(r, "ab $nosuch", a, &e) == NULL);
	ASSERT(strstr(e.msg, "$nosuch") != NULL);
	ASSERT_EQ(e.line, 1);
	ASSERT_EQ(e.col, 4); /* plain compile: offset 3 + 1 */
	bst_loc loc = { "site.conf", 12, 9 };
	ASSERT(bst_tpl_compile_with(r, cs("ab $nosuch"), &loc, false, a, &e) == NULL);
	ASSERT_STR(e.file, "site.conf");
	ASSERT_EQ(e.line, 12);
	ASSERT_EQ(e.col, 9); /* the arg's start; byte offset only in the message */
	ASSERT(strstr(e.msg, "$nosuch") != NULL && strstr(e.msg, "byte 3") != NULL);
	ASSERT(cmp(r, "$arg_", a, &e) == NULL); /* empty prefix suffix */
	bst_arena_free(a);
	bst_var_reg_free(r);
}

/* Columns after env expansion and escape decoding are not recoverable, so a quoted arg
 * with a decoded escape before the variable still reports the arg's own start. */
TEST(position_from_arg)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 16);
	bst_err e;
	const char *src = "d a;\nd \"x\\ny $nosuch\";\n";
	bst_ast *ast = bst_cfg_parse_string(src, strlen(src), "q.conf", NULL, a, &e);
	ASSERT(ast != NULL);
	const bst_ast_arg *arg = &ast->root.children->next->args[0];
	ASSERT_EQ(arg->kind, BST_TOK_STRING_TPL);
	/* compile via the explicit registry with the arg's tpl and loc */
	ASSERT(bst_tpl_compile_with(r, (bst_str){ arg->tpl, (uint32_t)arg->tpl_len }, &arg->loc,
				    false, a, &e) == NULL);
	ASSERT_STR(e.file, "q.conf");
	ASSERT_EQ(e.line, 2);
	ASSERT_EQ(e.col, arg->loc.col);
	ASSERT(strstr(e.msg, "$nosuch") != NULL);
	/* and the real-registry arg form reports the same position (no vars registered) */
	ASSERT(bst_tpl_compile_arg(arg, false, a, &e) == NULL);
	ASSERT_EQ(e.line, 2);
	ASSERT_EQ(e.col, arg->loc.col);
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(escape_dollar)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	struct bst_var_ctx c = mkctx(a);
	ASSERT(eq(bst_tpl_eval(cmp(r, "a$$host", a, &e), &c, a), "a$host"));
	ASSERT(eq(bst_tpl_eval(cmp(r, "$$$$", a, &e), &c, a), "$$"));
	ASSERT(eq(bst_tpl_eval(cmp(r, "\\$host", a, &e), &c, a), "$host")); /* \$host */
	ASSERT(eq(bst_tpl_eval(cmp(r, "a\\.php\\\\", a, &e), &c, a), "a\\.php\\\\"));
	ASSERT(eq(bst_tpl_eval(cmp(r, "\\\\$host", a, &e), &c, a), "\\$host"));
	ASSERT(eq(bst_tpl_eval(cmp(r, "end\\", a, &e), &c, a), "end\\"));
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(missing_value)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	struct bst_var_ctx c = mkctx(a);
	ASSERT(eq(bst_tpl_eval(cmp(r, "[$arg_zz]", a, &e), &c, a), "[]"));
	ASSERT(eq(bst_tpl_eval(cmp(r, "$arg_zz", a, &e), &c, a), ""));
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(name_rules)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	struct bst_var_ctx c = mkctx(a);
	ASSERT(eq(bst_tpl_eval(cmp(r, "$uri/x", a, &e), &c, a), "/p/x"));
	ASSERT(eq(bst_tpl_eval(cmp(r, "$arg_y&x", a, &e), &c, a), "Y&x"));
	ASSERT(eq(bst_tpl_eval(cmp(r, "$10", a, &e), &c, a), "C10")); /* $1 then 0 */
	ASSERT(cmp(r, "$2", a, &e) == NULL); /* not registered here */
	ASSERT(cmp(r, "$0", a, &e) == NULL);
	ASSERT(strstr(e.msg, "$0") != NULL);
	ASSERT(cmp(r, "cost $", a, &e) == NULL);
	ASSERT_EQ(e.col, 6);
	ASSERT(cmp(r, "$ x", a, &e) == NULL);
	ASSERT(cmp(r, "$-", a, &e) == NULL);
	ASSERT(cmp(r, "${HOME}", a, &e) == NULL);
	ASSERT(strstr(e.msg, "environment") != NULL);
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(crlf_in_value)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	struct bst_var_ctx c = mkctx(a);
	const char *bad[] = { "x\r\nSet-Cookie: a=b", "a\nb", "a\rb" };
	bst_tpl *t = bst_tpl_compile_header(cs("v=$http_x;"), a, &e);
	(void)t; /* real registry is empty: must fail */
	ASSERT(t == NULL);
	t = bst_tpl_compile_with(r, cs("v=$http_x;"), NULL, true, a, &e);
	ASSERT(t != NULL);
	bool unsafe = true;
	c.hdr = "clean";
	ASSERT(eq(bst_tpl_eval_header(t, &c, a, &unsafe), "v=clean;"));
	ASSERT(!unsafe);
	for (int i = 0; i < 3; i++) {
		c.hdr = bad[i];
		unsafe = false;
		bst_str s = bst_tpl_eval_header(t, &c, a, &unsafe);
		ASSERT(!bst_str_failed(s));
		ASSERT(unsafe);
	}
	/* NUL inside a value (length-delimited) */
	bst_tpl *nt = bst_tpl_compile_with(r, cs("a$nul"), NULL, true, a, &e);
	ASSERT(nt != NULL);
	unsafe = false;
	(void)bst_tpl_eval_header(nt, &c, a, &unsafe);
	ASSERT(unsafe);
	/* single-variable template (the no-copy path) is scanned too */
	bst_tpl *one = bst_tpl_compile_with(r, cs("$http_x"), NULL, true, a, &e);
	c.hdr = "a\r\nb";
	unsafe = false;
	(void)bst_tpl_eval_header(one, &c, a, &unsafe);
	ASSERT(unsafe);
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(header_literal_crlf)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	struct bst_var_ctx c = mkctx(a);
	/* a quoted "\n" decodes to a real LF before the template sees it */
	ASSERT(bst_tpl_compile_with(r, cs("a\nb"), &(bst_loc){ "h.conf", 3, 7 }, true, a, &e) == NULL);
	ASSERT_EQ(e.line, 3);
	ASSERT_EQ(e.col, 7);
	ASSERT(strstr(e.msg, "CR, LF or NUL") != NULL);
	ASSERT(bst_tpl_compile_with(r, (bst_str){ "a\0b", 3 }, NULL, true, a, &e) == NULL);
	ASSERT(bst_tpl_compile_with(r, cs("a\rb$host"), NULL, true, a, &e) == NULL);
	/* the same text compiles for non-header use, and eval_header still flags it */
	bst_tpl *t = cmp(r, "a\nb", a, &e);
	ASSERT(t != NULL);
	bool unsafe = false;
	bst_str s = bst_tpl_eval_header(t, &c, a, &unsafe);
	ASSERT(unsafe && s.len == 3);
	unsafe = true;
	ASSERT(eq(bst_tpl_eval_header(cmp(r, "ok", a, &e), &c, a, &unsafe), "ok"));
	ASSERT(!unsafe);
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(independent_of_input)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	struct bst_var_ctx c = mkctx(a);
	char in[] = "pre-$host-$arg_y-post";
	bst_tpl *t = cmp(r, in, a, &e);
	memset(in, 'Z', sizeof in - 1);
	ASSERT(eq(bst_tpl_eval(t, &c, a), "pre-ex.com-Y-post"));
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(overflow_and_alloc_failure)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	struct bst_var_ctx c = mkctx(a);
	bool unsafe = false;
	/* two values of ~4 GB: the total exceeds UINT32_MAX, a failure and not a wrap */
	bst_tpl *t = cmp(r, "$huge$huge", a, &e);
	ASSERT(t != NULL);
	bst_str s = bst_tpl_eval_header(t, &c, a, &unsafe);
	ASSERT(bst_str_failed(s) && s.len == 0 && unsafe);
	s = bst_tpl_eval(t, &c, a);
	ASSERT(bst_str_failed(s) && s.len == 0);
	/* injected arena failure: distinguishable from an empty result */
	t = cmp(r, "a$host", a, &e);
	bst_tpl_test_fail_alloc = 1;
	unsafe = false;
	s = bst_tpl_eval_header(t, &c, a, &unsafe);
	bst_tpl_test_fail_alloc = 0;
	ASSERT(bst_str_failed(s) && s.len == 0 && unsafe);
	ASSERT(eq(bst_tpl_eval(t, &c, a), "aex.com"));
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(registry_rules)
{
	bst_err e;
	bst_var_reg *r = bst_var_reg_new();
	ASSERT_EQ(bst_var_register(r, "host", v_host, &e), 0);
	ASSERT_EQ(bst_var_register(r, "host", v_uri, &e), -1);
	ASSERT(strstr(e.msg, "duplicate") != NULL);
	ASSERT_EQ(bst_var_register_prefix(r, "arg_", v_arg, &e), 0);
	ASSERT_EQ(bst_var_register_prefix(r, "arg_", v_arg, &e), -1);
	ASSERT_EQ(bst_var_register_prefix(r, "arg_x", v_arg, &e), -1); /* overlaps a prefix */
	ASSERT_EQ(bst_var_register(r, "arg_count", v_uri, &e), -1);    /* under a prefix */
	ASSERT_EQ(bst_var_register_prefix(r, "ho", v_arg, &e), -1);    /* above an exact name */
	ASSERT_EQ(bst_var_register(r, "bad-name", v_uri, &e), -1);
	ASSERT_EQ(bst_var_register(r, "0", v_uri, &e), -1);
	ASSERT_EQ(bst_var_register(r, "9", v_uri, &e), 0);
	ASSERT_EQ(bst_var_register(r, "10", v_uri, &e), -1);
	bst_var_reg_free(r);

	/* tables, with the same checks; the real registry is untouched (empty here) */
	static const bst_var_def good[] = { { "host", v_host, false }, { "arg_", v_arg, true } };
	static const bst_var_def dup[] = { { "host", v_uri, false } };
	const bst_vartab tg = { good, 2 }, td = { dup, 1 };
	const bst_vartab *ok[] = { &tg }, *bad[] = { &tg, &td };
	r = bst_var_reg_build(ok, 1, &e);
	ASSERT(r != NULL);
	bst_var_reg_free(r);
	ASSERT(bst_var_reg_build(bad, 2, &e) == NULL);
	ASSERT(strstr(e.msg, "host") != NULL);
	size_t n = 7;
	(void)bst_vartabs(&n);
	ASSERT_EQ(n, 0);
	ASSERT(bst_var_registry(&e) != NULL);
}

/* Schema integration through the explicit hook. */
static const bst_var_reg *hook_reg;
static int test_hook(const bst_ast_arg *a, bst_err *e)
{
	bst_arena *tmp = bst_arena_new(1 << 12);
	int rc = bst_tpl_compile_with(hook_reg, (bst_str){ a->tpl, (uint32_t)a->tpl_len }, &a->loc,
				      false, tmp, e) ? 0 : -1;
	bst_arena_free(tmp);
	return rc;
}
static int noop(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e;
	return 0;
}

TEST(schema_hook)
{
	static const bst_directive dirs[] = {
		{ .name = "ret", .contexts = BST_CTX_GLOBAL, .doc = "d", .apply = noop,
		  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_TEMPLATE } } } },
	};
	const bst_dirtab tab = { dirs, 1 };
	const bst_dirtab *tabs[] = { &tab };
	bst_err e;
	bst_schema *sc = bst_schema_build(tabs, 1, &e);
	ASSERT(sc != NULL);
	bst_var_reg *r = mkreg();
	hook_reg = r;
	bst_arena *a = bst_arena_new(1 << 16);
	const char *good = "ret /a/$host/$arg_q;", *bad = "ret /a/$nosuch;";
	bst_ast *ast = bst_cfg_parse_string(bad, strlen(bad), "s.conf", NULL, a, &e);
	ASSERT(ast != NULL);
	ASSERT_EQ(bst_cfg_validate_with(sc, ast, &e), 0); /* no hook: not checked */
	bst_schema_set_tpl_check(test_hook);
	ASSERT_EQ(bst_cfg_validate_with(sc, ast, &e), -1);
	ASSERT(strstr(e.msg, "$nosuch") != NULL);
	ASSERT_STR(e.file, "s.conf");
	ASSERT_EQ(e.line, 1);
	ast = bst_cfg_parse_string(good, strlen(good), "s.conf", NULL, a, &e);
	ASSERT_EQ(bst_cfg_validate_with(sc, ast, &e), 0);
	bst_schema_set_tpl_check(NULL);
	bst_arena_free(a);
	bst_schema_free(sc);
	bst_var_reg_free(r);
}

TAP_MAIN()

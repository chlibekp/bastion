#include "config/compile.h"
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
static bst_str v_nullv(const bst_var_ctx *c, bst_str sfx)
{
	(void)c, (void)sfx;
	return (bst_str){ NULL, 5 }; /* a NULL value is empty whatever its len */
}
static bst_str v_half(const bst_var_ctx *c, bst_str sfx)
{
	(void)c, (void)sfx;
	return (bst_str){ "h", 0x80000000u }; /* never dereferenced */
}
static bst_str v_halfm(const bst_var_ctx *c, bst_str sfx)
{
	(void)c, (void)sfx;
	return (bst_str){ "h", 0x7fffffffu };
}
static bst_str v_huge(const bst_var_ctx *c, bst_str sfx)
{
	(void)c, (void)sfx;
	/* Never dereferenced: tests using it fail on the total before any byte is read. */
	return (bst_str){ "x", UINT32_MAX - 1 };
}

static bst_var_reg *mkreg(void)
{
	bst_err e;
	bst_var_reg *r = bst_var_reg_new();
	if (!r || bst_var_register(r, "host", v_host, &e) || bst_var_register(r, "uri", v_uri, &e) ||
	    bst_var_register(r, "huge", v_huge, &e) || bst_var_register(r, "nul", v_nul, &e) || bst_var_register(r, "nullv", v_nullv, &e) ||
	    bst_var_register(r, "half", v_half, &e) || bst_var_register(r, "halfm", v_halfm, &e) || bst_var_register(r, "1", v_cap1, &e) ||
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
	return bst_tpl_compile_with(r, cs(s), NULL, a, e);
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
	ASSERT(bst_tpl_compile_with(r, cs("ab $nosuch"), &loc, a, &e) == NULL);
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
				    a, &e) == NULL);
	ASSERT_STR(e.file, "q.conf");
	ASSERT_EQ(e.line, 2);
	ASSERT_EQ(e.col, arg->loc.col);
	ASSERT(strstr(e.msg, "$nosuch") != NULL);
	/* and the real-registry arg form reports the same position (no vars registered) */
	ASSERT(bst_tpl_compile_arg(arg, a, &e) == NULL);
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
	ASSERT(bst_tpl_compile_header(cs("v=$http_x;"), a, &e) == NULL); /* real registry: empty */
	bst_header_tpl *t = bst_tpl_compile_header_with(r, cs("v=$http_x;"), NULL, a, &e);
	ASSERT(t != NULL);
	bst_str out = { "junk", 4 };
	c.hdr = "clean\ttab";
	ASSERT_EQ(bst_header_tpl_eval(t, &c, a, &out), BST_TPL_OK);
	ASSERT(eq(out, "v=clean\ttab;"));
	const char *bad[] = { "x\r\nSet-Cookie: a=b", "a\nb", "a\rb", "a\001b", "a\037b", "a\177b" };
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		c.hdr = bad[i];
		out = (bst_str){ "junk", 4 };
		ASSERT_EQ(bst_header_tpl_eval(t, &c, a, &out), BST_TPL_UNSAFE);
		ASSERT(out.len == 0 && out.p != NULL); /* ignoring the status cannot inject */
	}
	/* NUL inside a value (length-delimited) */
	bst_header_tpl *nt = bst_tpl_compile_header_with(r, cs("a$nul"), NULL, a, &e);
	out = (bst_str){ "junk", 4 };
	ASSERT_EQ(bst_header_tpl_eval(nt, &c, a, &out), BST_TPL_UNSAFE);
	ASSERT_EQ(out.len, 0);
	/* the single-variable (no copy) path is scanned and returns nothing either */
	bst_header_tpl *one = bst_tpl_compile_header_with(r, cs("$http_x"), NULL, a, &e);
	c.hdr = "a\r\nInj: 1";
	out = (bst_str){ "junk", 4 };
	ASSERT_EQ(bst_header_tpl_eval(one, &c, a, &out), BST_TPL_UNSAFE);
	ASSERT_EQ(out.len, 0);
	c.hdr = "fine";
	ASSERT_EQ(bst_header_tpl_eval(one, &c, NULL, &out), BST_TPL_OK);
	ASSERT(eq(out, "fine"));
	/* plain eval does not scan: it is the non-header API */
	c.hdr = "a\r\nb";
	ASSERT_EQ(bst_tpl_eval(cmp(r, "$http_x", a, &e), &c, a).len, 4);
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
	ASSERT(bst_tpl_compile_header_with(r, cs("a\nb"), &(bst_loc){ "h.conf", 3, 7 }, a, &e) == NULL);
	ASSERT_EQ(e.line, 3);
	ASSERT_EQ(e.col, 7);
	ASSERT(strstr(e.msg, "CR, LF, NUL") != NULL);
	ASSERT(bst_tpl_compile_header_with(r, (bst_str){ "a\0b", 3 }, NULL, a, &e) == NULL);
	ASSERT(bst_tpl_compile_header_with(r, cs("a\rb$host"), NULL, a, &e) == NULL);
	ASSERT(bst_tpl_compile_header_with(r, cs("a\001"), NULL, a, &e) == NULL);
	ASSERT(bst_tpl_compile_header_with(r, cs("a\177"), NULL, a, &e) == NULL);
	ASSERT(bst_tpl_compile_header_with(r, cs("lone"), NULL, a, &e) != NULL);
	bst_header_tpl *t = bst_tpl_compile_header_with(r, cs("a\tb"), NULL, a, &e);
	ASSERT(t != NULL); /* HTAB is allowed */
	bst_str out;
	ASSERT_EQ(bst_header_tpl_eval(t, &c, a, &out), BST_TPL_OK);
	ASSERT(eq(out, "a\tb"));
	/* the same text compiles for plain use */
	ASSERT(cmp(r, "a\nb", a, &e) != NULL);
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
	bst_str out = { "junk", 4 };
	bst_header_tpl *ht = bst_tpl_compile_header_with(r, cs("$huge$huge"), NULL, a, &e);
	ASSERT(ht != NULL);
	ASSERT_EQ(bst_header_tpl_eval(ht, &c, a, &out), BST_TPL_FAIL);
	ASSERT(out.len == 0 && out.p != NULL);
	bst_tpl *t = cmp(r, "$huge$huge", a, &e);
	ASSERT(bst_str_failed(bst_tpl_eval(t, &c, a)));

	/* Exact boundary, without allocating 4 GB: the test hook records the size asked of
	 * the arena and refuses it. 0x7fffffff+0x80000000 = UINT32_MAX is attempted; 2^32 is
	 * refused before any allocation (and does not wrap to 0). */
	bst_tpl_test_fail_alloc = 1;
	bst_tpl_test_alloc_req = 0;
	t = cmp(r, "$halfm$half", a, &e);
	ASSERT(bst_str_failed(bst_tpl_eval(t, &c, a)));
	ASSERT_EQ(bst_tpl_test_alloc_req, 0xffffffffu);
	bst_tpl_test_alloc_req = 0;
	t = cmp(r, "$half$half", a, &e);
	ASSERT(bst_str_failed(bst_tpl_eval(t, &c, a)));
	ASSERT_EQ(bst_tpl_test_alloc_req, 0); /* refused on the total, never asked */
	t = cmp(r, "$half$half$halfm", a, &e);
	ASSERT(bst_str_failed(bst_tpl_eval(t, &c, a)));
	ASSERT_EQ(bst_tpl_test_alloc_req, 0);
	bst_tpl_test_fail_alloc = 0;
	/* a single value of exactly UINT32_MAX is returned as is */
	static bst_var_reg *r2;
	r2 = bst_var_reg_new();
	ASSERT_EQ(bst_var_register(r2, "m", v_huge, &e), 0);
	ASSERT(bst_tpl_eval(cmp(r2, "$m", a, &e), &c, NULL).len == UINT32_MAX - 1);
	bst_var_reg_free(r2);

	/* injected arena failure: FAIL, distinguishable from an empty result */
	t = cmp(r, "a$host", a, &e);
	ht = bst_tpl_compile_header_with(r, cs("a$host"), NULL, a, &e);
	bst_tpl_test_fail_alloc = 1;
	ASSERT_EQ(bst_header_tpl_eval(ht, &c, a, &out), BST_TPL_FAIL);
	ASSERT_EQ(out.len, 0);
	bst_tpl_test_fail_alloc = 0;
	ASSERT(eq(bst_tpl_eval(t, &c, a), "aex.com"));
	ASSERT_EQ(bst_header_tpl_eval(ht, &c, a, &out), BST_TPL_OK);
	ASSERT(eq(out, "aex.com"));
	bst_arena_free(a);
	bst_var_reg_free(r);
}

TEST(null_value_is_empty)
{
	bst_var_reg *r = mkreg();
	bst_arena *a = bst_arena_new(1 << 12);
	bst_err e;
	struct bst_var_ctx c = mkctx(a);
	/* a stale len next to a NULL pointer must not be copied or counted */
	ASSERT(eq(bst_tpl_eval(cmp(r, "a$nullv|", a, &e), &c, a), "a|"));
	bst_str s = bst_tpl_eval(cmp(r, "$nullv", a, &e), &c, NULL);
	ASSERT(!bst_str_failed(s) && s.len == 0);
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
	ASSERT_EQ(bst_var_register(r, "arg", v_uri, &e), -1); /* a prefix of a prefix */
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
				      tmp, e) ? 0 : -1;
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

/* The registry-based entry installs the hook itself: an unknown variable fails through the
 * real path (a directive registered in this binary's own section). */
static const bst_directive real_dirs[] = {
	{ .name = "ret", .contexts = BST_CTX_GLOBAL, .doc = "d", .apply = noop,
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_TEMPLATE } } } },
};
BST_DIRECTIVES(real_dirs);

TEST(real_path_rejects_unknown_var)
{
	bst_err e;
	bst_arena *a = bst_arena_new(1 << 16);
	const char *bad = "ret /a/$nosuch;", *ok = "ret /a/$$x;";
	bst_ast *ast = bst_cfg_parse_string(bad, strlen(bad), "r.conf", NULL, a, &e);
	ASSERT(ast != NULL);
	bst_schema_set_tpl_check(NULL);
	bst_config *cfg = bst_cfg_compile(ast, &e);
	ASSERT(cfg == NULL);
	ASSERT(strstr(e.msg, "$nosuch") != NULL);
	ASSERT_STR(e.file, "r.conf");
	ASSERT_EQ(e.line, 1);
	ast = bst_cfg_parse_string(ok, strlen(ok), "r.conf", NULL, a, &e);
	cfg = bst_cfg_compile(ast, &e);
	ASSERT(cfg != NULL);
	bst_config_free(cfg);
	bst_schema_set_tpl_check(NULL);
	bst_arena_free(a);
}

TAP_MAIN()

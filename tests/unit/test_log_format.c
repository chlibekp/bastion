/* Access log line rendering and escaping (src/ops/log_format.c). */
#include "config/template.h"
#include "core/arena.h"
#include "ops/log_format.h"
#include "tap.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Fixture ctx: the opaque bst_var_ctx is defined here, never by the module. */
struct bst_var_ctx {
	const char *v;
	size_t vlen;
};

static bst_str v_val(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return (bst_str){ c->v, (uint32_t)c->vlen };
}

static bst_var_reg *mkreg(void)
{
	bst_err e = { .msg = "" };
	bst_var_reg *r = bst_var_reg_new();
	if (r == NULL || bst_var_register(r, "v", v_val, &e) != 0)
		abort();
	return r;
}

static bst_tpl *cmp(const bst_var_reg *r, const char *s, bst_arena *a)
{
	bst_err e = { .msg = "" };
	bst_tpl *t = bst_tpl_compile_with(r, (bst_str){ s, (uint32_t)strlen(s) }, NULL, a, &e);
	if (t == NULL)
		abort();
	return t;
}

/* Escapes p[0..n) with esc into a NUL-terminated static buffer. */
static const char *run(bst_tpl_esc esc, const char *p, size_t n)
{
	static char out[256];
	size_t w = esc(out, sizeof out - 1, p, n);
	if (w == SIZE_MAX)
		return "<nofit>";
	out[w] = '\0';
	return out;
}

/* Every byte of a JSON string body is printable ASCII, and escapes are well formed. */
static bool json_body_valid(const char *s)
{
	for (const char *p = s; *p != '\0'; p++) {
		unsigned char c = (unsigned char)*p;
		if (c < 0x20 || c == 0x7f || c == '"')
			return false;
		if (c == '\\') {
			p++;
			if (*p == 'u') {
				for (int i = 1; i <= 4; i++)
					if (strchr("0123456789abcdef", p[i]) == NULL || p[i] == '\0')
						return false;
				p += 4;
			} else if (strchr("\"\\nrt", *p) == NULL || *p == '\0') {
				return false;
			}
		}
	}
	return true;
}

TEST(json_escaping)
{
	static const char in[] = "a\"b\\c\n\r\t\x01\x1f\x7f";
	ASSERT_STR(run(bst_logfmt_json_esc, in, sizeof in - 1),
		   "a\\\"b\\\\c\\n\\r\\t\\u0001\\u001f\\u007f");
	/* invalid UTF-8 (a lone continuation, an overlong, a cut sequence) becomes U+FFFD */
	static const char bad[] = "\x80x\xc0\xafy\xe2\x82";
	const char *o = run(bst_logfmt_json_esc, bad, sizeof bad - 1);
	ASSERT(json_body_valid(o));
	ASSERT(strstr(o, "\\ufffd") != NULL && strchr(o, 'x') != NULL && strchr(o, 'y') != NULL);
	/* C1 controls and U+2028/2029 end lines in some readers: escaped too */
	ASSERT_STR(run(bst_logfmt_json_esc, "\xc2\x85|\xe2\x80\xa8|\xe2\x80\xa9", 10),
		   "\\u0085|\\u2028|\\u2029");
	/* valid UTF-8 passes as it is */
	ASSERT_STR(run(bst_logfmt_json_esc, "caf\xc3\xa9", 5), "caf\xc3\xa9");
}

TEST(json_escaping_every_byte)
{
	char in[256];
	for (int i = 0; i < 256; i++)
		in[i] = (char)i;
	static char out[256 * 6 + 1];
	size_t w = bst_logfmt_json_esc(out, sizeof out - 1, in, sizeof in);
	ASSERT(w != SIZE_MAX);
	out[w] = '\0';
	ASSERT(json_body_valid(out));
}

TEST(text_escaping)
{
	/* CR and LF cannot split a line; quotes cannot close the format's own */
	ASSERT_STR(run(bst_logfmt_text_esc, "a\r\nb\"c\\d", 8), "a\\x0d\\x0ab\\x22c\\x5cd");
	ASSERT_STR(run(bst_logfmt_text_esc, "\xff\xe2\x80\xa8\xc3\xa9", 6),
		   "\\xff\\xe2\\x80\\xa8\xc3\xa9");
	/* the operator's literal text passes, except control bytes */
	ASSERT_STR(run(bst_logfmt_text_lit, "\"[x]\"\n", 6), "\"[x]\"\\x0a");
}

TEST(escaper_reports_no_fit)
{
	char out[4];
	ASSERT_EQ(bst_logfmt_json_esc(out, sizeof out, "\n\n\n", 3), SIZE_MAX);
	ASSERT_EQ(bst_logfmt_text_esc(out, sizeof out, "\n", 1), 4);
	ASSERT_EQ(bst_logfmt_text_esc(out, sizeof out, "a\n", 2), SIZE_MAX);
}

TEST(render_json_line)
{
	bst_arena *a = bst_arena_new(4096);
	bst_var_reg *r = mkreg();
	bst_logfmt_field fields[2] = { { "lit", cmp(r, "x\"y", a) }, { "val", cmp(r, "<$v>", a) } };
	bst_logfmt f = { .name = "j", .json = true, .fields = fields, .nfields = 2 };
	struct bst_var_ctx c = { .v = "\"}\n{\"evil\":1", .vlen = 12 };
	char out[256];
	size_t n = bst_logfmt_render(&f, &c, out, sizeof out);
	ASSERT(n > 0);
	out[n] = '\0';
	ASSERT_STR(out, "{\"lit\":\"x\\\"y\",\"val\":\"<\\\"}\\n{\\\"evil\\\":1>\"}\n");
	ASSERT_EQ(memchr(out, '\n', n - 1) == NULL, 1); /* one line */
	bst_var_reg_free(r);
	bst_arena_free(a);
}

TEST(render_text_value_cap_and_line_cap)
{
	bst_arena *a = bst_arena_new(4096);
	bst_var_reg *r = mkreg();
	bst_logfmt f = { .name = "t", .json = false, .text = cmp(r, "[$v]", a) };
	char *big = malloc(5000);
	memset(big, 'a', 5000);
	struct bst_var_ctx c = { .v = big, .vlen = 5000 };
	static char out[BST_ACCESS_LINE_MAX];
	size_t n = bst_logfmt_render(&f, &c, out, sizeof out);
	ASSERT_EQ(n, BST_LOG_VALUE_MAX + 3); /* cut to 2 KiB, brackets and newline */
	ASSERT(out[n - 1] == '\n' && out[n - 2] == ']');
	/* a line that does not fit is not written at all */
	ASSERT_EQ(bst_logfmt_render(&f, &c, out, 100), 0);
	free(big);
	bst_var_reg_free(r);
	bst_arena_free(a);
}

TAP_MAIN()

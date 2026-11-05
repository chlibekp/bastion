/* libFuzzer harness for template compilation and evaluation. Arbitrary bytes are compiled
 * (plain and header forms) against a fixture registry, then evaluated with values that
 * hold CR and LF. Properties: no crash, output bounded by the input plus the values, and
 * `unsafe` is set whenever CR, LF or NUL reach the output. */
#include "config/template.h"

#include <stdlib.h>
#include <string.h>

struct bst_var_ctx {
	bst_arena *a;
};

static bst_str v_crlf(const bst_var_ctx *c, bst_str s)
{
	(void)c, (void)s;
	return BST_S("a\r\nb");
}
static bst_str v_plain(const bst_var_ctx *c, bst_str s)
{
	(void)c;
	return s.len ? s : BST_S("plain");
}
static bst_str v_none(const bst_var_ctx *c, bst_str s)
{
	(void)c, (void)s;
	return (bst_str){ NULL, 0 };
}

#define VAL_MAX 6 /* longest fixture value */

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size > 4096)
		return 0;
	static bst_var_reg *reg;
	if (reg == NULL) {
		bst_err be;
		reg = bst_var_reg_new();
		if (!reg || bst_var_register(reg, "crlf", v_crlf, &be) ||
		    bst_var_register(reg, "plain", v_plain, &be) ||
		    bst_var_register(reg, "none", v_none, &be) ||
		    bst_var_register(reg, "1", v_crlf, &be) ||
		    bst_var_register_prefix(reg, "arg_", v_plain, &be) ||
		    bst_var_register_prefix(reg, "http_", v_crlf, &be))
			abort();
	}
	char *copy = malloc(size ? size : 1);
	if (!copy)
		abort();
	memcpy(copy, d, size);
	bst_str s = { copy, (uint32_t)size };

	bst_arena *a = bst_arena_new(1 << 16);
	bst_arena *scratch = bst_arena_new(1 << 16);
	bst_var_ctx *ctx = (bst_var_ctx *)(void *)&(struct bst_var_ctx){ scratch };
	bst_err e;
	for (int header = 0; header < 2; header++) {
		bst_tpl *t = bst_tpl_compile_with(reg, s, NULL, header, a, &e);
		if (t == NULL) {
			if (e.msg[0] == 0)
				abort();
			continue;
		}
		/* independent of the input from here on */
		memset(copy, 'Z', size);
		bool unsafe = false;
		bst_str out = bst_tpl_eval_header(t, ctx, scratch, &unsafe);
		if (bst_str_failed(out))
			abort(); /* small inputs: never a failure */
		if ((size_t)out.len > size * (VAL_MAX + 4096) + 1)
			abort();
		bool bad = false;
		for (uint32_t i = 0; i < out.len; i++)
			if (out.p[i] == '\r' || out.p[i] == '\n' || out.p[i] == 0)
				bad = true;
		if (bad && !unsafe)
			abort();
		if (header && bst_tpl_is_literal(t) && unsafe)
			abort(); /* header compile rejected unsafe literals */
		bst_str o2 = bst_tpl_eval(t, ctx, scratch);
		if (bst_str_failed(o2) || o2.len != out.len)
			abort();
		memcpy(copy, d, size);
		bst_arena_reset(scratch);
	}
	bst_arena_free(scratch);
	bst_arena_free(a);
	free(copy);
	return 0;
}

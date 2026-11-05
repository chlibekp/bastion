/* libFuzzer harness for config value parsers and schema validation. The input is copied
 * to an exact-size heap block so ASan flags reads past len. Properties: parsers never
 * crash and respect their ranges; any config text that parses can be validated against a
 * small table that uses every value type, with a clean result or an error message. */
#include "config/parser.h"
#include "config/schema.h"
#include "config/values.h"

#include <stdlib.h>
#include <string.h>

static int fz_apply(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e;
	return 0;
}

static const char *const fz_enum[] = { "a", "b", NULL };
static const char *const fz_kw[] = { "auto", NULL };
static const bst_optspec fz_opts[] = {
	{ .key = "k=", .type = { .kind = BST_T_DURATION } },
	{ .key = "n=", .type = { .kind = BST_T_PERCENT } },
	{ .key = "m=", .type = { .kind = BST_T_MODE } },
	{ .key = "l=", .type = { .kind = BST_T_INT, .min = 0, .max = 9, .keywords = fz_kw,
				 .list = true } },
};
#define FZ_ALL (BST_CTX_GLOBAL | BST_CTX_SERVER)
static const bst_directive fz_dirs[] = {
	{ .name = "d", .contexts = FZ_ALL, .repeatable = true, .doc = "fuzz", .require = true,
	  .child_ctx = BST_CTX_SERVER, .apply = fz_apply,
	  .args = { .min_args = 0, .max_args = 9, .opts = fz_opts, .nopts = 4,
		    .block = BST_BLOCK_OPTIONAL,
		    .pos = { { .kind = BST_T_SIZE }, { .kind = BST_T_RATE }, { .kind = BST_T_BOOL },
			     { .kind = BST_T_ENUM, .enum_values = fz_enum },
			     { .kind = BST_T_INT, .min = -5, .max = 5 }, { .kind = BST_T_CIDR },
			     { .kind = BST_T_PATH }, { .kind = BST_T_TEMPLATE } } } },
	{ .name = "w", .contexts = FZ_ALL, .subname = "x", .doc = "fuzz", .apply = fz_apply,
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_DURATION } } } },
	{ .name = "w", .contexts = FZ_ALL, .subname = "y", .doc = "fuzz", .apply = fz_apply,
	  .args = { .min_args = 0, .max_args = 0 } },
	{ .name = "any", .contexts = BST_CTX_SERVER, .any_name = true, .repeatable = true,
	  .doc = "fuzz", .apply = fz_apply,
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_SIZE } } } },
};
static const bst_dirtab fz_tab = { fz_dirs, sizeof fz_dirs / sizeof fz_dirs[0] };

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size > 4096)
		return 0;
	char *copy = malloc(size ? size : 1);
	if (!copy)
		abort();
	memcpy(copy, d, size);
	bst_str s = { copy, (uint32_t)size };

	uint64_t u;
	bst_rate r;
	bool b;
	size_t i;
	int64_t n;
	uint8_t p;
	(void)bst_parse_size(s, &u);
	(void)bst_parse_duration_us(s, &u);
	if (bst_parse_rate(s, &r) && (r.count == 0 || r.period_us == 0))
		abort();
	(void)bst_parse_bool(s, &b);
	(void)bst_parse_enum(s, fz_enum, &i);
	if (bst_parse_int(s, -5, 5, &n) && (n < -5 || n > 5))
		abort();
	if (bst_parse_percent(s, &p) && p > 100)
		abort();
	uint32_t mode;
	if (bst_parse_mode(s, &mode) && mode > 07777)
		abort();
	bst_str v;
	bool seen = false;
	(void)bst_parse_kv(s, "k=", &v, &seen);

	/* Fixture schema, built once. A NULL here would silently stop validation from being
	 * fuzzed, so it aborts. */
	static bst_schema *sc;
	if (sc == NULL) {
		bst_err be;
		const bst_dirtab *tabs[] = { &fz_tab };
		sc = bst_schema_build(tabs, 1, &be);
		if (sc == NULL)
			abort();
	}
	bst_arena *a = bst_arena_new(1 << 16);
	bst_err e;
	bst_cfg_opts o = { .no_include = 1 };
	bst_ast *ast = bst_cfg_parse_string(copy, size, "fuzz.conf", &o, a, &e);
	if (ast) {
		int rc = bst_cfg_validate_with(sc, ast, &e);
		if (rc != 0 && e.msg[0] == 0)
			abort();
	}
	bst_arena_free(a);
	free(copy);
	return 0;
}

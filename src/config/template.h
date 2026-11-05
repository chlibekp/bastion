/* Compiled variable templates: used by rewrites, redirects, headers and log formats. A
 * template is compiled once at config load into a flat array of literal and variable ops
 * and evaluated on the request path with attacker-influenced values.
 *
 * Input is the `tpl` form of a config arg (see parser.h), in which `$` that came from an
 * env value is already `$$`, so env data can never introduce a variable. Syntax:
 *   $$          a literal `$`.
 *   \$          a literal `$` (the backslash is dropped): the lexer keeps unknown escapes,
 *               so "\$host" reaches this code as \$host. Any other backslash is literal.
 *               The scan is left to right, one backslash at a time: in `\\$x` the first
 *               backslash is literal (it is followed by `\`) and the second one escapes `$`.
 *   $name       name matches [A-Za-z_][A-Za-z0-9_]*, longest match: `$uri/` is `$uri` then
 *               `/`, `$arg_y&x` stops at `&`. Looked up as an exact name, else as a prefix
 *               variable (`arg_`, `http_`, `cookie_`) whose rest is the suffix handed to
 *               the variable function. A prefix with an empty suffix (`$arg_`) is an error.
 *   $1 .. $9    regex captures, ONE digit only: `$10` is `$1` then the text `0`. They are
 *               ordinary registered variables named "1".."9".
 *   $0          compile error: Phase 5 rewrites only use `$1`..`$9` (the whole match is
 *               available as `$uri`), so `$0` is almost certainly a mistake.
 *   `$` at the end, or before anything else: compile error with position (a silent
 *   literal would hide typos). `${` is a compile error: env expansion runs earlier.
 * An unknown variable is a compile error naming it.
 *
 * Positions. bst_tpl_compile reports line 1 and col = byte offset in the template + 1,
 * file NULL. bst_tpl_compile_at / _arg report the ARG's start position (file:line:col of
 * its loc) with the byte offset in the message ("at byte N of the template"). Exact
 * columns are not recoverable: after env expansion and decoding of quoted escapes the
 * template offset no longer maps to a source column, so the start of the arg is used.
 *
 * Registry. Subsystems declare a static table and register it with BST_VARS(table), the
 * same linker-section mechanism as BST_DIRECTIVES, so everything is registered before the
 * config compiles and nothing is locked at runtime. A duplicate name, or a prefix that
 * collides with an exact name or another prefix (one starts with the other), is a startup
 * error: bst_var_registry returns NULL with err set. Test tables go through
 * bst_var_reg_new/bst_var_register/_prefix and the `_with` calls, never touching the real
 * registry.
 *
 * Variable functions: bst_str fn(const bst_var_ctx *, bst_str suffix). The ctx is opaque
 * here (Phase 4 and later define it) and carries the arena. A function returns an empty
 * bst_str for a missing value and allocates only when it must.
 *
 * Evaluation. bst_tpl_eval computes every value once, sums the lengths with overflow
 * checks, then does ONE arena allocation and copies. A literal-only template and a
 * template that is a single variable return their bytes with no allocation and no copy
 * (the result may then point into the template or into a variable's own storage). FAILURE
 * (arena exhaustion, or a total above UINT32_MAX) returns {NULL, 0}: test with
 * bst_str_failed(). An empty success has a non-NULL p.
 *
 * Header use. bst_tpl_eval_header additionally sets *unsafe when the output may contain
 * CR, LF or NUL: from an expanded value, or from a literal part (a literal can legally
 * hold \n through a quoted escape). The CALLER MUST then refuse the header (drop it and
 * log), or strip those bytes, and must never emit the string as is. On failure *unsafe is
 * also true. Use bst_tpl_compile_header for header templates: it rejects a literal part
 * with CR, LF or NUL at compile time, with position, so only values can trip `unsafe` at
 * runtime; eval_header still checks literals of a template compiled otherwise.
 *
 * Compiled templates live in the arena given to compile, never point into the input,
 * are immutable, and eval writes nothing to them: safe to share across forked workers. */
#ifndef BST_CONFIG_TEMPLATE_H
#define BST_CONFIG_TEMPLATE_H

#include "config/parser.h"
#include "core/arena.h"
#include "core/err.h"
#include "core/str.h"

#include <stdbool.h>
#include <stddef.h>

#define BST_TPL_MAX_OPS 128 /* literal and variable parts per template */

typedef struct bst_tpl bst_tpl;
typedef struct bst_var_ctx bst_var_ctx; /* opaque: defined by the request layer */
typedef bst_str (*bst_var_fn)(const bst_var_ctx *, bst_str suffix);

/* ---- Registry ---- */

typedef struct bst_var_def {
	const char *name; /* exact name, or the prefix when .prefix */
	bst_var_fn fn;
	bool prefix;
} bst_var_def;

typedef struct bst_vartab {
	const bst_var_def *defs;
	size_t n;
} bst_vartab;

#if defined(__has_attribute)
#if __has_attribute(retain)
#define BST_VAR_RETAIN_ __attribute__((retain))
#endif
#endif
#ifndef BST_VAR_RETAIN_
#define BST_VAR_RETAIN_
#endif

/* `static const bst_var_def vars[] = { {"host", var_host}, {"arg_", var_arg, true} };
 * BST_VARS(vars);` */
#define BST_VARS(table)                                                                 \
	static const bst_vartab bst_vartab_##table = { (table),                         \
						       sizeof(table) / sizeof((table)[0]) }; \
	static const bst_vartab *const bst_varptr_##table                               \
		__attribute__((used, section("bst_vars"))) BST_VAR_RETAIN_ =            \
			&bst_vartab_##table

typedef struct bst_var_reg bst_var_reg;

bst_var_reg *bst_var_reg_new(void);
void bst_var_reg_free(bst_var_reg *r);
/* 0, or -1 with err set: bad or duplicate name, or a prefix collision. Names are
 * identifiers, or one digit 1..9. */
int bst_var_register(bst_var_reg *r, const char *name, bst_var_fn fn, bst_err *err);
int bst_var_register_prefix(bst_var_reg *r, const char *prefix, bst_var_fn fn, bst_err *err);
/* Builds a registry from tables. NULL with err set on any failure. */
bst_var_reg *bst_var_reg_build(const bst_vartab *const *tabs, size_t n, bst_err *err);
/* The tables in the linker section; n is 0 when none. */
const bst_vartab *const *bst_vartabs(size_t *n);
/* The real registry, built once from the linker section (thread-safe, same result every
 * call). NULL with err set when a registration is invalid or duplicated. */
const bst_var_reg *bst_var_registry(bst_err *err);

/* ---- Compile ---- */

/* loc may be NULL. header: reject CR, LF and NUL in literal parts. */
bst_tpl *bst_tpl_compile_with(const bst_var_reg *r, bst_str s, const bst_loc *loc, bool header,
			      bst_arena *a, bst_err *err);
bst_tpl *bst_tpl_compile(bst_str s, bst_arena *a, bst_err *err);
bst_tpl *bst_tpl_compile_header(bst_str s, bst_arena *a, bst_err *err);
/* From a config arg (its tpl form), reporting at the arg's position. */
bst_tpl *bst_tpl_compile_arg(const bst_ast_arg *arg, bool header, bst_arena *a, bst_err *err);

/* Schema hook (see bst_schema_set_tpl_check): checks an arg against the real registry. */
int bst_tpl_check_arg(const bst_ast_arg *arg, bst_err *err);

/* ---- Eval ---- */

static inline bool bst_str_failed(bst_str s)
{
	return s.p == NULL;
}
bool bst_tpl_is_literal(const bst_tpl *t);
bst_str bst_tpl_eval(const bst_tpl *t, const bst_var_ctx *ctx, bst_arena *a);
bst_str bst_tpl_eval_header(const bst_tpl *t, const bst_var_ctx *ctx, bst_arena *a,
			    bool *unsafe);

#ifdef BST_TEST
extern int bst_tpl_test_fail_alloc; /* test hook: the eval allocation fails */
#endif

#endif

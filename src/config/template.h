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
 * checks, then does ONE arena allocation and copies. It never scans the bytes: it is
 * for non-header text only (log lines, bodies, redirect targets that are validated
 * elsewhere). A literal-only template and a template that is a single variable return
 * their bytes with no allocation and no copy. LIFETIME: the result may point into the
 * template or into a variable's own storage, so it is valid only until the ctx's backing
 * storage is reset or mutated; a caller that must keep it longer copies it.
 * FAILURE (arena exhaustion, or a total above UINT32_MAX) returns {NULL, 0}: test with
 * bst_str_failed(). An empty success has a non-NULL p. A variable that returns a NULL p
 * is treated as empty whatever its len.
 *
 * Header use. Anything that becomes a header field value (response or request, including
 * Location) MUST be built through bst_header_tpl, a distinct type: Phase 4 and later must
 * compile every header template with bst_tpl_compile_header* and evaluate it only with
 * bst_header_tpl_eval. The two types are incompatible, so passing one to the other's API
 * is a compile error. bst_header_tpl_eval returns BST_TPL_OK, BST_TPL_UNSAFE (a value
 * holds a forbidden byte) or BST_TPL_FAIL (as above); on anything but OK, *out is the
 * empty string, so a caller that ignores the status cannot inject. Forbidden bytes are
 * those RFC 9110 rejects in a field value: every control byte below 0x20 except HTAB
 * (so CR, LF, NUL), and 0x7F. A literal part containing one (for instance from a quoted
 * "\n" escape) is rejected when a header template is compiled, with position. The caller
 * on UNSAFE drops the header and logs; it never strips and emits.
 *
 * Variable names. `$http_user_agent` reaches the variable function as suffix
 * `user_agent`, unnormalised: mapping `_` to `-` and case folding are the function's
 * job. An exact name that is a prefix of a registered prefix (or the reverse) is rejected
 * at registration, as is any collision between two prefixes.
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

#define BST_TPL_MAX_OPS 1024 /* literal and variable parts per template: a text log_format of
			      * a few hundred variables fits */

typedef struct bst_tpl bst_tpl;
typedef struct bst_header_tpl bst_header_tpl; /* distinct from bst_tpl on purpose */
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

/* loc may be NULL. */
bst_tpl *bst_tpl_compile_with(const bst_var_reg *r, bst_str s, const bst_loc *loc,
			      bst_arena *a, bst_err *err);
bst_tpl *bst_tpl_compile(bst_str s, bst_arena *a, bst_err *err);
/* From a config arg (its tpl form), reporting at the arg's position. */
bst_tpl *bst_tpl_compile_arg(const bst_ast_arg *arg, bst_arena *a, bst_err *err);

/* Header templates: literal parts with a forbidden byte are a compile error. */
bst_header_tpl *bst_tpl_compile_header_with(const bst_var_reg *r, bst_str s, const bst_loc *loc,
					    bst_arena *a, bst_err *err);
bst_header_tpl *bst_tpl_compile_header(bst_str s, bst_arena *a, bst_err *err);
bst_header_tpl *bst_tpl_compile_header_arg(const bst_ast_arg *arg, bst_arena *a, bst_err *err);

/* Schema hook (see bst_schema_set_tpl_check): checks an arg against the real registry.
 * Wired into the registry schema in registry.c. */
int bst_tpl_check_arg(const bst_ast_arg *arg, bst_err *err);

/* True when name is a variable of the real registry (exact or prefix form): lets the parser
 * say "write $name" when an unset ${name} was probably meant as a variable. */
bool bst_tpl_var_known(const char *name);

/* The function of the variable a template begins with, NULL when it begins with literal text
 * (or is empty). For config-time checks such as "this redirect target starts with request
 * input". */
bst_var_fn bst_tpl_first_var(const bst_tpl *t);
bst_var_fn bst_header_tpl_first_var(const bst_header_tpl *t);

/* ---- Eval ---- */

typedef enum bst_tpl_status {
	BST_TPL_OK = 0,
	BST_TPL_UNSAFE, /* a value holds a forbidden header byte */
	BST_TPL_FAIL,	/* arena exhausted, or the total exceeds UINT32_MAX */
} bst_tpl_status;

static inline bool bst_str_failed(bst_str s)
{
	return s.p == NULL;
}
bool bst_tpl_is_literal(const bst_tpl *t);
bst_str bst_tpl_eval(const bst_tpl *t, const bst_var_ctx *ctx, bst_arena *a);
/* *out is the empty string unless the result is BST_TPL_OK. */
int bst_header_tpl_eval(const bst_header_tpl *t, const bst_var_ctx *ctx, bst_arena *a,
			bst_str *out);

#ifdef BST_TEST
extern int bst_tpl_test_fail_alloc; /* test hook: the eval allocation fails */
extern size_t bst_tpl_test_alloc_req; /* test hook: size of the last allocation attempted */
#endif

#endif

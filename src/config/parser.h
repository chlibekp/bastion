/* Config parser: tokens to AST, with includes and environment expansion. Iterative: an
 * explicit block stack, no recursion in parsing or in AST walks, so deeply nested input
 * hits BST_CFG_MAX_NESTING instead of the C stack. Only include handling recurses, and
 * only up to BST_CFG_MAX_INCLUDE_DEPTH.
 *
 * Grammar: statement = WORD arg* (';' | '{' statement* '}'). The directive name must be a
 * bare WORD (a quoted name is an error, and the name is never env-expanded). An empty
 * statement `;` is an error. A block's braces must close in the file that opened them.
 *
 * AST: every string (name, arg text, file names in loc) is NUL-terminated and lives in the
 * caller's arena, so the AST and err->file stay valid while the arena does. Children form
 * a singly linked list (children, then ->next) with a parent pointer, so a walk needs no
 * recursion: use bst_ast_next. `include` never appears in the AST: included nodes are
 * spliced in place, each keeping the loc of the file and line it came from.
 *
 * Environment expansion. `${NAME}` and `${NAME:-default}` expand inside one token, in
 * WORD and STRING_TPL, never in STRING_RAW. NAME must match [A-Za-z_][A-Za-z0-9_]*, else
 * an error. An unset variable without a default is an error naming it. An EMPTY value
 * counts as set, so `${X:-y}` with X="" gives the empty string. The default is literal
 * text and is not expanded again. Expansion happens on the token text, after lexing, so a
 * value can never create tokens: `;`, `}`, `#`, quotes and whitespace stay inside the one
 * argument. A `$` followed by `{` in a WORD or STRING_TPL is always an env reference.
 *
 * Template safety. Each arg carries two forms. `text` is the final value (env values
 * inserted verbatim); this is what a plain-string directive uses. `tpl` is the same string
 * made safe to hand to the template compiler: every `$` that came from an env value or a
 * default is doubled to `$$`, while `$` written in the config source is untouched (that
 * is how `$host` stays a variable). Env data therefore cannot introduce template
 * variables. For STRING_RAW (no processing), `tpl` has every `$` doubled: a single-quoted
 * string is never a template. Without env-derived or raw `$`, tpl == text (same pointer).
 *
 * Bounds, each a clear error naming the limit. */
#ifndef BST_CONFIG_PARSER_H
#define BST_CONFIG_PARSER_H

#include "config/lexer.h"
#include "core/arena.h"
#include "core/err.h"

#include <stddef.h>

#define BST_CFG_MAX_INCLUDE_DEPTH 16 /* nested includes; the root file is depth 0 */
#define BST_CFG_MAX_NESTING 64	     /* open blocks, counted across includes */
#define BST_CFG_MAX_FILES 4096	     /* files read per parse, repeats counted */
#define BST_CFG_MAX_BYTES ((size_t)64 << 20) /* total bytes read from files per parse */
#define BST_CFG_MAX_ARGS 256	     /* arguments per statement */
#define BST_CFG_MAX_ARG_BYTES ((size_t)1 << 20) /* one arg after expansion */
#define BST_CFG_MAX_EXPANDED ((size_t)64 << 20) /* all args after expansion, per parse */

typedef struct bst_loc {
	const char *file; /* arena string */
	int line;
	int col;
} bst_loc;

typedef struct bst_ast_arg {
	bst_tok_kind kind; /* WORD, STRING_TPL or STRING_RAW */
	const char *text;  /* NUL-terminated, env expanded */
	size_t len;
	const char *tpl; /* template-safe form, see above */
	size_t tpl_len;
	bst_loc loc;
} bst_ast_arg;

typedef struct bst_ast_node {
	const char *name; /* NUL-terminated; NULL only in the root */
	size_t name_len;
	bst_ast_arg *args;
	size_t nargs;
	int has_block;			 /* written with { } (children may be empty) */
	struct bst_ast_node *children;	 /* first child */
	size_t nchildren;
	struct bst_ast_node *next;	 /* next sibling */
	struct bst_ast_node *parent;	 /* the root node for top-level statements */
	struct bst_ast_node *tail;	 /* internal: last child */
	bst_loc loc;			 /* the directive name */
} bst_ast_node;

typedef struct bst_ast {
	bst_ast_node root; /* name NULL; top-level statements are its children */
} bst_ast;

typedef struct bst_cfg_opts {
	int no_include; /* `include` is an error: input cannot read host files (fuzzing) */
	const char *base_dir; /* parse_string: relative includes resolve here; NULL means cwd */
} bst_cfg_opts;

/* On failure returns NULL and fills err (file is arena-owned, line/col 1-based). opts may
 * be NULL (includes enabled). text need not be NUL-terminated; name labels it in errors. */
bst_ast *bst_cfg_parse_string(const char *text, size_t len, const char *name,
			      const bst_cfg_opts *opts, bst_arena *a, bst_err *err);
bst_ast *bst_cfg_parse_file(const char *path, bst_arena *a, bst_err *err);

/* Pre-order successor without recursion. n == NULL gives the first node. */
const bst_ast_node *bst_ast_next(const bst_ast *ast, const bst_ast_node *n);

#endif

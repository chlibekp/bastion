/* Effective-config printer (`bastion -T`) and the schema dump (`--dump-schema`).
 *
 * bst_cfg_dump prints a compiled AST as config text: includes are already flattened and
 * environment already expanded by the parser, so the output has no `include` and no
 * `${...}`. It can therefore contain secrets that came from the environment.
 *
 * Order. Statements keep source order inside a scope; defaults follow. A default is
 * printed in the scope where its directive first becomes valid (the same rule compile
 * uses), only when the scope does not set it, and children inherit it, so printing never
 * overrides an inherited value with a default.
 *
 * Fixed point. Printing the output again gives the same bytes: defaults are explicit by
 * then and arguments are quoted the same way.
 *
 * Quoting. Each argument is printed so that re-lexing gives the same `text` and the same
 * template-safe `tpl` (see parser.h), which is checked by actually re-parsing the
 * candidate: bare word, "double" or 'single', in an order that keeps the original token
 * kind where possible. A single-quoted string keeps `$` literal (its tpl has `$$`),
 * which is how an env-derived `$` stays literal. An argument no spelling can reproduce
 * (for instance an env value with both a single quote and a `$`) is an error, never a
 * different meaning. */
#ifndef BST_CONFIG_DUMP_H
#define BST_CONFIG_DUMP_H

#include "config/parser.h"
#include "config/schema.h"
#include "core/err.h"

#include <stdio.h>

/* Prints the AST (already validated against s) to out. 0, or -1 with err set; nothing is
 * written to out on failure. */
int bst_cfg_dump(const bst_schema *s, const bst_ast *ast, FILE *out, bst_err *err);

/* Prints every directive of s as one JSON document to out. 0, or -1 with err set. */
int bst_schema_dump_json(const bst_schema *s, FILE *out, bst_err *err);

#endif

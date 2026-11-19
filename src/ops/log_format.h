/* Access log formats (Phase 14, Task 3): `log_format <name> json { field $var; ... }` and
 * `log_format <name> text "<template>"`, compiled at config load and rendered into one line per
 * request by the worker that served it.
 *
 * Injection. Every variable's value is escaped on its own (bst_tpl_write), so nothing a client
 * sends can end a line or close a quote:
 *   json  a JSON string: quote, backslash and control bytes escaped, C1 controls and U+2028/2029
 *         as \uXXXX, bytes that are not valid UTF-8 as U+FFFD. Every line is one valid JSON
 *         object.
 *   text  values: quote, backslash, control bytes, DEL, C1 controls, U+2028/2029 and invalid
 *         UTF-8 bytes as \xHH. Literal text of the template is the operator's and passes, except
 *         control bytes, which are \xHH too.
 * A value longer than BST_LOG_VALUE_MAX bytes is cut there before escaping; a line that still
 * does not fit BST_ACCESS_LINE_MAX is not written (the caller counts it as dropped). */
#ifndef BST_OPS_LOG_FORMAT_H
#define BST_OPS_LOG_FORMAT_H

#include "config/template.h"

#include <stdbool.h>
#include <stddef.h>

#define BST_LOG_VALUE_MAX 2048
#define BST_ACCESS_LINE_MAX 16384 /* bytes of one line, newline included */

typedef struct bst_logfmt_field {
	const char *name; /* the JSON key, as written in the config */
	const bst_tpl *tpl;
} bst_logfmt_field;

typedef struct bst_logfmt {
	const char *name;
	bool json;
	const bst_tpl *text; /* text formats */
	bst_logfmt_field *fields; /* json formats, file order */
	size_t nfields, fields_cap_;
} bst_logfmt;

/* Escapers in the bst_tpl_esc shape: bytes written, or SIZE_MAX when they do not fit. */
size_t bst_logfmt_json_esc(char *out, size_t cap, const char *p, size_t n);
size_t bst_logfmt_text_esc(char *out, size_t cap, const char *p, size_t n);
size_t bst_logfmt_text_lit(char *out, size_t cap, const char *p, size_t n);

/* One line with its newline into out. Bytes written, or 0 when it does not fit cap. */
size_t bst_logfmt_render(const bst_logfmt *f, const bst_var_ctx *ctx, char *out, size_t cap);

#endif

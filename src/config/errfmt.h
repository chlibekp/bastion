/* Error-message helpers shared by the schema, the compiler and the directive tables.
 *
 * One quoting rule for untrusted text that goes into a message: bst_cfg_shown and
 * bst_cfg_shown_file copy at most a bounded number of bytes (BST_SCHEMA_MAX_TOKEN_SHOWN for
 * a token, BST_CFG_SHOWN_FILE for a file name), replace every byte that is not printable
 * ASCII, and the quote and backslash too, by '?', and append "..." when cut. A producer
 * never copies raw input into bst_err.msg (see core/err.h); file names in messages
 * included. */
#ifndef BST_CONFIG_ERRFMT_H
#define BST_CONFIG_ERRFMT_H

#include "config/parser.h"
#include "core/err.h"

#include <stddef.h>

#define BST_CFG_SHOWN_FILE 120 /* file-name bytes echoed in an error message */

/* out needs room for the limit plus 4 bytes (BST_SCHEMA_MAX_TOKEN_SHOWN + 8 is used). */
void bst_cfg_shown(const char *s, size_t len, char *out, size_t cap);
/* A file name (NULL gives "?"). */
void bst_cfg_shown_file(const char *file, char *out, size_t cap);

/* Sets err's file, line and col from loc (the file stays the AST's); NULL clears them. */
void bst_cfg_err_at(bst_err *err, const bst_loc *loc);

#endif

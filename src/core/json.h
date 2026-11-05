/* Strict JSON (RFC 8259) parser and writer for untrusted input (JWT claims, ACME,
 * admin API). Choices that pin otherwise ambiguous behaviour:
 *  - Input need not be NUL-terminated; nothing is read past len. len must be below 4 GiB.
 *  - A leading BOM and any content after the top-level value (other than whitespace)
 *    are errors. Whitespace is space, \t, \n, \r only.
 *  - Nesting deeper than BST_JSON_MAX_DEPTH is an error (compile-time constant).
 *  - Duplicate object keys are errors, compared after unescaping. Detection is O(n)
 *    expected: pairwise for small objects, otherwise a SipHash-1-3 table with a random key.
 *  - Strings and keys must be valid UTF-8 (no overlong forms, surrogates or values above
 *    U+10FFFF). \u escapes must be valid; surrogate pairs combine, lone surrogates fail.
 *  - A string or key containing U+0000 (via \u0000) is rejected, so every string returned
 *    by bst_json_str is also NUL-terminated at p[len] and has no interior NUL.
 *  - Numbers follow the JSON grammar exactly. Their source text is kept verbatim.
 *  - All nodes live in the caller's arena; an arena failure is reported as an error. */
#ifndef BST_JSON_H
#define BST_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/arena.h"
#include "core/err.h"
#include "core/str.h"

#define BST_JSON_MAX_DEPTH 64

typedef struct bst_json bst_json;

typedef enum bst_json_type {
	BST_JSON_NULL,
	BST_JSON_BOOL,
	BST_JSON_NUM,
	BST_JSON_STR,
	BST_JSON_ARR,
	BST_JSON_OBJ,
} bst_json_type;

/* NULL on any error, with details in err (may be NULL). */
bst_json *bst_json_parse(bst_arena *a, const char *s, size_t len, bst_err *err);

bst_json_type bst_json_typeof(const bst_json *j);
/* True and sets *out only if j is a boolean. */
bool bst_json_bool(const bst_json *j, bool *out);
/* True and sets *out only if j is a string. out->p is NUL-terminated at p[len]. */
bool bst_json_str(const bst_json *j, bst_str *out);
/* True and sets *out to the verbatim number text if j is a number. */
bool bst_json_num_text(const bst_json *j, bst_str *out);

typedef enum bst_json_int_rc {
	BST_JSON_INT_OK,
	BST_JSON_INT_NOT_NUMBER,
	BST_JSON_INT_NOT_INTEGER,  /* has a nonzero fractional part, e.g. 1.5 or 1e-1 */
	BST_JSON_INT_RANGE,        /* |value| > 2^53-1 */
} bst_json_int_rc;

/* Exact decimal evaluation, no floating point. Integral values written with a fraction
 * or exponent are integers (1.0 and 1e2 give 1 and 100). -0 gives 0. The accepted range
 * is [-(2^53-1), 2^53-1]. *out is written only on BST_JSON_INT_OK. */
bst_json_int_rc bst_json_int(const bst_json *j, int64_t *out);

/* Member lookup in an object by NUL-terminated key; NULL if absent or j is not an
 * object. Linear in the member count. */
const bst_json *bst_json_get(const bst_json *obj, const char *key);
/* Element count of an array, or member count of an object; 0 for other types. */
size_t bst_json_arr_len(const bst_json *arr);
/* NULL if arr is not an array or i is out of range. */
const bst_json *bst_json_arr_at(const bst_json *arr, size_t i);
/* Object iteration in source order: key of member i and its value; NULL if out of range. */
const bst_json *bst_json_obj_at(const bst_json *obj, size_t i, bst_str *key);

/* Writer. Output accumulates in a malloc'd buffer. Misuse and failure are sticky: the first
 * error (allocation, invalid UTF-8 or NUL in a bst_jw_str string, nesting past
 * BST_JSON_MAX_DEPTH, a mismatched close, bst_jw_key outside an object or twice in a row,
 * a value in an object without a key, a second top-level value, a key with no value)
 * makes later calls do nothing and bst_jw_finish return false. Exactly one top-level value
 * is required. Strings are escaped (quote, backslash, control characters as \u00XX or
 * short forms). A successful finish yields syntactically valid JSON text; duplicate keys
 * are the caller's responsibility. */
typedef struct bst_jw {
	char *buf;
	size_t len;
	size_t cap;
	bool err;
	bool after_key;
	int depth;
	bool top_done;
	char kind[BST_JSON_MAX_DEPTH + 1];  /* 'o' or 'a' per open container */
	bool first[BST_JSON_MAX_DEPTH + 1];
} bst_jw;

void bst_jw_init(bst_jw *w);
void bst_jw_free(bst_jw *w);
/* True if no error occurred; then w->buf (NUL-terminated) and w->len are the output. */
bool bst_jw_finish(bst_jw *w);
void bst_jw_obj_begin(bst_jw *w);
void bst_jw_obj_end(bst_jw *w);
void bst_jw_arr_begin(bst_jw *w);
void bst_jw_arr_end(bst_jw *w);
void bst_jw_key(bst_jw *w, bst_str k);
void bst_jw_str(bst_jw *w, bst_str s);
/* Like bst_jw_str but never fails on content: invalid UTF-8 bytes and U+0000 become
 * U+FFFD, and C1 controls, U+2028 and U+2029 are written as \\uXXXX. For logs. */
void bst_jw_str_lossy(bst_jw *w, bst_str s);
void bst_jw_int(bst_jw *w, int64_t v);
void bst_jw_bool(bst_jw *w, bool v);
void bst_jw_null(bst_jw *w);
/* Writes a parsed tree back out (numbers verbatim). */
void bst_jw_value(bst_jw *w, const bst_json *j);

#ifdef BST_TEST
/* Test builds only: replaces getrandom(2), used for the hash key of large objects. NULL
 * restores the real call. If getrandom fails the parse fails; there is no fallback key. */
#include <sys/types.h>
extern ssize_t (*bst_json_getrandom_hook)(void *buf, size_t n, unsigned flags);
#endif

#endif

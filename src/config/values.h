/* Typed value parsers for config arguments. All are strict and whole-token: the entire
 * input must be the value, with no sign, space, float, locale or libc strtol behaviour
 * (so dev and release builds accept the same text). Input is a bst_str and need not be
 * NUL-terminated. A leading zero in a multi-digit number is an error everywhere (0600
 * read as decimal 600 would be a permission bug); modes are the one octal reader. Overflow is an error, checked before multiplying. Units are
 * case-sensitive. On failure *out is left untouched. */
#ifndef BST_CONFIG_VALUES_H
#define BST_CONFIG_VALUES_H

#include "core/str.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bytes. Decimal digits with an optional binary suffix: k (2^10), m (2^20), g (2^30).
 * "512", "16k", "1m", "2g". 18446744073709551615 passes, ...616 and 17179869184g fail. */
bool bst_parse_size(bst_str s, uint64_t *out);

/* Microseconds. Digits and a mandatory unit: us, ms, s, m (minutes), h, d, y (365 days).
 * "0s" is valid. */
bool bst_parse_duration_us(bst_str s, uint64_t *out);

/* A rate is `count` events per `period_us`, kept exact: 6000/m is {6000, 60000000} and
 * 5/m is {5, 60000000}, never rounded to a whole number per second. Syntax:
 * <digits>[k]/<s|m>. The count takes the size suffix k, which means 1024 here as in
 * sizes (so 1k/s is 1024 per second); the count is never 0. period_us is 1000000 for
 * /s and 60000000 for /m. */
typedef struct bst_rate {
	uint64_t count;
	uint64_t period_us;
} bst_rate;
bool bst_parse_rate(bst_str s, bst_rate *out);
/* Same rate (a.count / a.period_us == b.count / b.period_us), computed exactly. */
bool bst_rate_eq(const bst_rate *a, const bst_rate *b);

/* "on" or "off" only. */
bool bst_parse_bool(bst_str s, bool *out);

/* values is NULL-terminated; exact, case-sensitive match. *idx is the match position. */
bool bst_parse_enum(bst_str s, const char *const *values, size_t *idx);

/* File mode: 3 or 4 octal digits ("0600", "755"). */
bool bst_parse_mode(bst_str s, uint32_t *out);

/* Optional '-', then decimal digits, within [min, max]. No '+', no leading space. */
bool bst_parse_int(bst_str s, int64_t min, int64_t max, int64_t *out);

/* Digits then '%', 0..100. */
bool bst_parse_percent(bst_str s, uint8_t *out);

/* Matches a `key=value` argument; key includes the '=' (for example "weight="). Returns
 * 1 and sets *val (the text after the key) when arg starts with key, 0 when it does not,
 * and -1 on an empty value or when *seen is already true (a repeated key). *seen is set
 * to true on a match. */
int bst_parse_kv(bst_str arg, const char *key, bst_str *val, bool *seen);

#endif

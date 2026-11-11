/* Conditional requests (RFC 9110 section 13): If-Match, If-Unmodified-Since, If-None-Match,
 * If-Modified-Since, in the order of section 13.2.2, and the validators a file gives. Pure
 * functions: no I/O, no clock, so the proxy cache (a later phase) reuses them. */
#ifndef BST_HTTP_CONDITIONAL_H
#define BST_HTTP_CONDITIONAL_H

#include "http/headers.h"
#include "http/http.h"

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

typedef struct bst_validators {
	bool has_etag;
	bst_str etag; /* as sent on the wire: "\"abc\"", or "W/\"abc\"" */
	bool has_mtime;
	time_t mtime; /* seconds */
} bst_validators;

typedef enum bst_cond_result {
	BST_COND_PROCEED, /* send the representation (or the range) */
	BST_COND_304,
	BST_COND_412,
} bst_cond_result;

/* Evaluates the request's conditional headers against the validators. A date that does not parse
 * is ignored (section 13.1.3); If-Match and If-None-Match use the strong and the weak comparison. */
bst_cond_result bst_evaluate_preconditions(const bst_headers *req, const bst_validators *v,
					   bst_method method);

/* HTTP-date in any of the three formats of section 5.6.7 (IMF-fixdate, obsolete RFC 850,
 * asctime). false when it is none of them. */
bool bst_http_date_parse(bst_str s, time_t *out);

/* The strong ETag of a file: "<hex mtime_ns>-<hex size>", quoted. Writes at most cap bytes with a
 * NUL; returns the length, 0 when cap is too small. */
size_t bst_etag_format(int64_t mtime_ns, int64_t size, char *out, size_t cap);

#define BST_ETAG_MAX 48

#endif

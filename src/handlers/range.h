/* Range requests (RFC 9110 section 14): parsing `Range: bytes=...` against a size, and the
 * If-Range test. Pure functions, reused by the proxy cache. */
#ifndef BST_HANDLERS_RANGE_H
#define BST_HANDLERS_RANGE_H

#include "core/str.h"

#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

/* An inclusive byte range, 0 <= start <= end < size. */
typedef struct bst_range {
	off_t start, end;
} bst_range;

typedef enum bst_range_status {
	BST_RANGE_NONE = 0, /* no usable Range: send the whole thing with 200 */
	BST_RANGE_OK,	    /* *n ranges, ascending, not overlapping, not adjacent */
	BST_RANGE_416,	    /* a valid header, and nothing in it lies inside the file */
} bst_range_status;

/* Parses one Range header value for a representation of size bytes into out (room for max).
 *  - another unit than bytes, a syntax error, or more than max range specs (counting those that
 *    fall outside the file): NONE, as the RFC allows ("MAY ignore").
 *  - a spec past the end is dropped; one that reaches past it is clamped; a suffix longer than the
 *    file is the whole file. If none remains: 416.
 *  - overlapping and adjacent ranges are merged and the result is sorted, so 10,000 specs cost one
 *    bounded pass and can never ask for more than the file's size in total.
 * Numbers past 2^63-1 saturate and never overflow. */
int bst_range_parse(bst_str header, off_t size, bst_range *out, int max, int *n);

/* If-Range: true when the Range may be honoured. value is the If-Range header (an entity-tag or an
 * HTTP-date); etag is the response's strong ETag (empty when it has none), mtime its
 * Last-Modified. A weak tag, a mismatch or an unparsable value gives false: the full body. */
bool bst_if_range_ok(bst_str value, bst_str etag, bool has_mtime, time_t mtime);

#endif

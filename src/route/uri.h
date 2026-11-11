/* Request-path normalization (RFC 3986 sections 2.1, 5.2.4 and 6) and query lookup. The router
 * and the file handler never see a raw path: everything below `root` is reached through the
 * output of bst_uri_normalize, and openat2(RESOLVE_BENEATH) is the second wall behind it. */
#ifndef BST_ROUTE_URI_H
#define BST_ROUTE_URI_H

#include "core/str.h"

#include <stddef.h>

typedef enum bst_uri_flags {
	BST_URI_MERGE_SLASHES = 1,	/* "//a///b" becomes "/a/b" */
	BST_URI_ALLOW_ENCODED_SLASH = 2, /* "%2f" decodes to a separator; else it is an error */
} bst_uri_flags;

/* Why a path was refused. All of them are a 400 for the client. */
enum {
	BST_URI_OK = 0,
	BST_URI_E_FORM = -1,	  /* not an absolute path (no leading '/'), or empty */
	BST_URI_E_PERCENT = -2,	  /* a '%' not followed by two hex digits */
	BST_URI_E_NUL = -3,	  /* "%00" */
	BST_URI_E_SLASH = -4,	  /* "%2f" and the flag is off */
	BST_URI_E_SPACE = -5,	  /* out has no room: cap must be at least raw_path.len + 1 */
};

/* Percent-decodes raw_path once ("%252e" is the three bytes "%2e", never a dot), removes dot
 * segments the way RFC 3986 section 5.2.4 does (a ".." above the root is dropped: "/../x" is
 * "/x"), and with BST_URI_MERGE_SLASHES collapses runs of '/'. A backslash is an ordinary
 * byte. A trailing slash survives ("/a/" stays, "/a/.." is "/"). The result is written to out
 * (never longer than the input) followed by a NUL that out_len does not count. Returns
 * BST_URI_OK, or one of the errors above with *out_len untouched. out may equal raw_path.p:
 * the work is done in place. */
int bst_uri_normalize(bst_str raw_path, char *out, size_t cap, bst_uri_flags flags,
		      size_t *out_len);

/* Percent-encodes in as a URI path: unreserved characters and '/' stay, every other byte
 * (including '%') becomes %XX. Returns 0, or -1 when cap is too small (cap must hold the
 * result and a NUL). Inverse of the decode step: normalize(encode(normalize(x))) is
 * normalize(x). */
int bst_uri_encode_path(bst_str in, char *out, size_t cap, size_t *out_len);

/* The first parameter called name in query ("a=1&b=2", no '?'), as written (not decoded) in
 * *value; a bare "name" has an empty value. 1 when found, 0 when not. */
int bst_query_get(bst_str query, bst_str name, bst_str *value);

#endif

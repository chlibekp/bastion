/* Cache-Control (RFC 9111 section 5.2) and its targeted twin CDN-Cache-Control (RFC 9213), parsed
 * into flags and delta-seconds. The input is hostile: a field is a comma-separated list of
 * `token [ "=" ( token / quoted-string ) ]`; anything else in an element makes that element
 * unknown and it is skipped. A directive whose argument is not a valid delta-seconds (letters,
 * a sign, more than 10 digits, a value above 2^31) or that is repeated with a different value
 * marks the whole field `invalid`: the policy then treats the response as stale (RFC 9111
 * section 4.2.1 allows that, and it is the safe choice for a shared cache). Pure functions. */
#ifndef BST_HTTP_CACHE_CONTROL_H
#define BST_HTTP_CACHE_CONTROL_H

#include "http/headers.h"

#include <stdbool.h>
#include <stdint.h>

#define BST_CC_NONE (-1) /* a delta-seconds directive that was not given */

typedef struct bst_cache_control {
	bool present;	       /* at least one field line */
	bool invalid;	       /* a malformed or contradictory delta-seconds */
	bool no_store, no_cache, priv, pub, must_revalidate, proxy_revalidate, immutable;
	bool no_transform, only_if_cached;
	int64_t max_age, s_maxage, max_stale, min_fresh, swr, sie; /* seconds, or BST_CC_NONE */
	bool max_stale_any;	/* max-stale with no value: any staleness */
} bst_cache_control;

void bst_cc_init(bst_cache_control *cc);
/* Adds the directives of one field value to cc (call once per field line). */
void bst_cc_parse_value(bst_str v, bst_cache_control *cc);
/* Every Cache-Control line of h. Returns cc->present. */
bool bst_cc_parse(const bst_headers *h, bst_cache_control *cc);
/* Every line of the named field (CDN-Cache-Control). Returns cc->present. */
bool bst_cc_parse_name(const bst_headers *h, bst_str name, bst_cache_control *cc);

#endif

/* RFC 9111 rules of a shared cache, as pure functions: may a response be stored, how long is it
 * fresh, how old is it, does a stored variant fit a new request, what may a client force, and
 * what a 304 changes. No I/O, no clock: callers pass times (seconds since the epoch), so the
 * tests can move time. Section numbers below are RFC 9111 unless named otherwise.
 *
 * Shared-cache choices that go beyond the RFC's minimum, for safety:
 *  - An error response (4xx, 5xx) is stored only with explicit freshness or a `cache_valid`
 *    rule naming its status: heuristic freshness never applies to it.
 *  - A response with Set-Cookie is not stored unless `cache_cookies_policy strip` says to
 *    store it with the Set-Cookie fields removed.
 *  - A request with Authorization is stored only as section 3.5 allows (public, s-maxage,
 *    must-revalidate).
 *  - A client's Cache-Control (no-cache, max-age=0) is obeyed only with
 *    `cache_honor_request_cc on`, so clients cannot force load onto the origin by default.
 *  - A malformed Cache-Control makes the response stale (section 4.2.1). */
#ifndef BST_CACHE_POLICY_H
#define BST_CACHE_POLICY_H

#include "http/cache_control.h"
#include "http/http.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* `cache_valid [status...] time`: status 0 matches any status. */
typedef struct bst_cache_valid {
	int status;
	int64_t secs;
} bst_cache_valid;

typedef enum bst_cache_cookies {
	BST_CACHE_COOKIES_NO_STORE = 0, /* a response with Set-Cookie is not stored */
	BST_CACHE_COOKIES_STRIP,	/* stored without its Set-Cookie fields */
} bst_cache_cookies;

/* cache_ignore_headers: the response fields the policy pretends are absent. */
enum {
	BST_CACHE_IGN_CACHE_CONTROL = 1u << 0,
	BST_CACHE_IGN_EXPIRES = 1u << 1,
	BST_CACHE_IGN_SET_COOKIE = 1u << 2,
	BST_CACHE_IGN_VARY = 1u << 3,
	BST_CACHE_IGN_CDN_CACHE_CONTROL = 1u << 4,
};

typedef struct bst_cache_policy_cfg {
	const bst_cache_valid *valid; /* cache_valid, in order: the first matching status wins */
	size_t nvalid;
	bool honor_request_cc;	      /* cache_honor_request_cc */
	bst_cache_cookies cookies;    /* cache_cookies_policy */
	uint32_t ignore;	      /* BST_CACHE_IGN_* */
	unsigned vary_limit;	      /* cache_vary_limit: more Vary names than this is not stored */
	int64_t heuristic_max;	      /* cap of heuristic freshness, seconds (0: no heuristics) */
} bst_cache_policy_cfg;

/* Why a response is not stored (for logs and Cache-Status detail), or NULL when it may be. */
bool bst_cache_storable(const bst_req_head *req, int status, const bst_headers *resp,
			const bst_cache_policy_cfg *cfg, const char **reason);

typedef struct bst_freshness {
	int64_t lifetime;     /* seconds; 0 or less: stale at once */
	bool no_cache;	      /* every use needs a successful revalidation */
	bool must_revalidate; /* never served stale (must-revalidate, proxy-revalidate, s-maxage) */
	bool immutable;
	int64_t swr, sie;     /* stale-while-revalidate, stale-if-error windows, or BST_CC_NONE */
	const char *source;   /* "cdn-cache-control", "s-maxage", "max-age", "expires",
				 "cache_valid", "heuristic", "none" */
} bst_freshness;

/* Section 4.2.1, with CDN-Cache-Control first (RFC 9213: when present, Cache-Control is not
 * used for freshness), then s-maxage, max-age, Expires minus Date, `cache_valid`, heuristics. */
void bst_cache_freshness(int status, const bst_headers *resp, const bst_cache_policy_cfg *cfg,
			 int64_t now, bst_freshness *out);

/* Section 4.2.3: the current age. date and age_value are BST_CC_NONE when absent. */
int64_t bst_cache_age(int64_t date, int64_t age_value, int64_t req_time, int64_t resp_time,
		      int64_t now);
/* Date and Age of a response, BST_CC_NONE when absent or malformed. */
void bst_cache_resp_times(const bst_headers *resp, int64_t *date, int64_t *age);

/* With `cache_honor_request_cc on`: the request asks for revalidation (no-cache, max-age=0,
 * Pragma: no-cache without Cache-Control). Always false when off. */
bool bst_cache_req_revalidate(const bst_headers *req, const bst_cache_policy_cfg *cfg);
/* Whether the request forbids storing (no-store in its Cache-Control: always obeyed). */
bool bst_cache_req_no_store(const bst_headers *req);

#define BST_CACHE_VARY_MAX 4096 /* the longest Vary data an entry keeps */

/* The Vary data of a response for a request: one line per nominated field, "name:value\n",
 * name lower case, value with whitespace runs folded to one space, trimmed, repeated lines
 * joined with ",". Returns the length; -1 for Vary: * (never matches), -2 when it does not fit
 * cap or names more fields than limit (0: no limit). An absent Vary gives 0. */
int bst_cache_vary_data(const bst_headers *resp, const bst_headers *req, unsigned limit, char *out,
			size_t cap);
/* Does a stored variant (its response fields and the Vary data stored with it) fit req? */
bool bst_cache_key_vary_match(bst_str stored_vary, const bst_headers *stored_resp,
			      const bst_headers *req);

/* A successful (2xx, 3xx) response to an unsafe method invalidates the target (section 4.4). */
bool bst_cache_invalidates(bst_method m, int status);

/* Section 4.3.4: the 304's fields replace the stored ones of the same name, except those that
 * frame the message or the connection. New entries take the bytes from stored's arena. 0, -1 on
 * exhaustion. */
int bst_cache_merge_304(bst_headers *stored, const bst_headers *resp304);

#endif

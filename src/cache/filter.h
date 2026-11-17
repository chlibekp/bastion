/* The cache in front of the proxy handler (architecture section 5: lookup before the handler,
 * a tee of the response into the store). The proxy handler calls these hooks; everything about
 * caching lives here.
 *
 *   request     bst_cache_request: a request in a scope with `cache` is looked up (the RAM tier,
 *               then the shared index and the disk object on the aio pool). A fresh hit is
 *               answered here, with Age and Cache-Status (RFC 9211), conditionals (304) and a
 *               single Range (206). A miss or a stale entry is forwarded through the proxy with
 *               a bst_cfill attached: the client's validators are dropped so the full response
 *               comes back to be stored, and a stale entry's own validators are sent instead.
 *   head        bst_cache_on_head: decides storage (cache/policy.h), starts the object, adds
 *               Cache-Status; a 304 to a revalidation is answered here from the stored object.
 *   body, end   bst_cache_on_body copies the body into the object; bst_cache_finish commits it
 *               only after the upstream's response ended cleanly, so a truncated or failed
 *               response is never stored; anything else aborts it.
 *
 * Keys. `cache_key` (default $scheme$host$request_uri) hashed with SHA-256. A response with Vary
 * is stored under the key plus its Vary data (policy.h), and a small marker object under the key
 * itself names the Vary fields, so each variant is a separate object.
 *
 * Validity across workers. The shared index decides: an object the index does not hold (evicted,
 * invalidated, purged) is a miss in every worker, RAM copies included, and a RAM copy is used
 * only while the index entry has the same fill time. */
#ifndef BST_CACHE_FILTER_H
#define BST_CACHE_FILTER_H

#include "http/stream.h"

#include <stdbool.h>

typedef struct bst_cfill bst_cfill;

/* Continues a request through the proxy, with cf (NULL: no caching) attached. */
typedef void (*bst_cache_forward_fn)(bst_stream *s, bst_cfill *cf);

/* At the start of a proxied request. Returns false when the cache has nothing to do with it (the
 * caller proxies it as usual). True when the cache took it: it answers it itself, or calls
 * forward (now or later) with the bst_cfill the response hooks below take. *slot holds the
 * cfill meanwhile, for bst_cache_reset. */
bool bst_cache_request(bst_stream *s, bst_cfill **slot, bst_cache_forward_fn forward);
/* The stream ended while the cache had it (a lookup in flight). */
void bst_cache_reset(bst_cfill *cf);

/* The request fields for the upstream: the client's validators and Range removed when filling,
 * the stored validators added when revalidating. 0, or -1 on exhaustion. */
int bst_cache_upstream_headers(bst_cfill *cf, bst_headers *hs);

typedef enum bst_cache_head_rc {
	BST_CACHE_HEAD_SEND = 0, /* send the (possibly amended) head as usual */
	BST_CACHE_HEAD_DONE,	 /* the cache answered the client: drop the upstream's response */
} bst_cache_head_rc;

/* The final response head from the upstream: uh as received, out what the client is about to
 * get (Cache-Status is added to it, the tag header removed). */
bst_cache_head_rc bst_cache_on_head(bst_cfill *cf, int status, const bst_headers *uh,
				    bst_resp_head *out, bool end);
/* Response body bytes on their way to the client (memory segments are copied). Called by the
 * store filter bst_cache_on_head puts on the stream after compress (upstream -> compress ->
 * cache store), so a compressed response is stored as sent; the proxy no longer tees itself. */
void bst_cache_on_body(bst_cfill *cf, const bst_chain *c);
/* An upstream failure before any response byte reached the client: true when the cache
 * answered (stale-if-error). */
bool bst_cache_on_error(bst_cfill *cf, int status);
/* The exchange is over: complete means the upstream's response ended cleanly and every byte
 * was seen. Commits or aborts the object and frees cf. client_gone: the client left first. */
void bst_cache_finish(bst_cfill *cf, bool complete, bool client_gone);

#endif

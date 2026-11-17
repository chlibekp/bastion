/* Forward auth: before the handler, a GET to an auth service (a named upstream) carrying the
 * request's credentials and its X-Original-Method, X-Original-URI, X-Original-Host and
 * X-Original-Proto. A 2xx lets the request in, with the listed response headers copied onto
 * it; a 401, 403 or 3xx goes back to the client as the service sent it, body included.
 * Anything else (a timeout, a refused connection, a 5xx, a malformed answer) is 503: it fails
 * closed and there is no fail-open option. The request body is never sent to the service.
 * Client-sent copies of the X-Original-* fields and of the copied response headers are always
 * removed first, so neither the service nor the upstream can be told a spoofed value. */
#ifndef BST_AUTH_FORWARD_H
#define BST_AUTH_FORWARD_H

#include <stddef.h>
#include <stdint.h>

struct bst_cfg_upstream;

typedef struct bst_fwd_cfg {
	const char *upstream;		  /* as written */
	struct bst_cfg_upstream *up;	  /* resolved by the post hook */
	const char *path;		  /* default "/" */
	uint64_t timeout_ms;		  /* default 5s */
	const char *const *pass;	  /* request headers sent to the service */
	size_t npass;
	const char *const *resp;	  /* service response headers copied to the request */
	size_t nresp;
} bst_fwd_cfg;

#endif

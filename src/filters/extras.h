/* The small HTTP features of Phase 11, Task 3, all per scope (bst_cfg_extras):
 *
 *   early_hints.c       103 Early Hints with the configured Link values, before the handler.
 *   request_id.c        a 128-bit request ID: kept from a trusted peer or made, forwarded
 *                       upstream in the request and echoed in the response.
 *   security_headers.c  the basic and strict presets with per-header overrides.
 *   maintenance.c       503 with Retry-After for everyone outside maintenance_allow.
 *
 * The response-side work runs in bst_stream_send_head after the header operations, so it
 * applies to every handler and protocol, error pages included. */
#ifndef BST_FILTERS_EXTRAS_H
#define BST_FILTERS_EXTRAS_H

#include "http/stream.h"

#include <stdbool.h>

/* Router, once the location is known, before the request header operations: sets
 * s->request_id and puts it in the request headers (replacing the client's copy unless the
 * peer is trusted). */
void bst_request_id_apply(bst_stream *s);

/* Router: answers 503 when the scope is in maintenance and the peer is not allowed. True when
 * it answered (the request is over). */
bool bst_maintenance_check(bst_stream *s);

/* Router, just before the handler starts: the 103 Early Hints response when configured. */
void bst_early_hints_send(bst_stream *s);

/* bst_stream_send_head: the request ID and the security headers on a final response. */
void bst_extras_response_head(bst_stream *s, bst_resp_head *h);

/* True when the request arrived over TLS (HTTPS, or HTTP/3). */
bool bst_stream_is_tls(const bst_stream *s);

#endif

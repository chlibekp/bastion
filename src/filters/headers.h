/* Response header operations (`header_add`, `header_set`, `header_remove`, `expires`): the first
 * stage of the response filter chain, run on every response head a handler or the server sends
 * (bst_stream_send_head), errors included. */
#ifndef BST_FILTERS_HEADERS_H
#define BST_FILTERS_HEADERS_H

#include "http/stream.h"

/* Applies s->cfg's operations to h in place, in order: global, server, location. h's header list
 * is extended or edited, so pass a copy of what the handler gave. */
void bst_filter_response_headers(bst_stream *s, bst_resp_head *h);

#endif

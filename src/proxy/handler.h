/* The reverse proxy handler (architecture section 5): a request on any protocol becomes one
 * HTTP/1.1 exchange with an upstream peer (or one stream of an HTTP/2 connection for an upstream
 * with `protocol http2`, proxy/client_h2.h), streamed both ways with backpressure.
 *
 * Guarantees:
 *  - Nothing of the client's bytes passes unparsed: the request head is written anew from the
 *    parsed request, with hop-by-hop fields, Connection-nominated fields and framing removed and
 *    the forwarding fields regenerated (forward_headers.c). The response head is parsed strictly
 *    (http/h1/resp_parser.h) and rebuilt the same way.
 *  - A response that breaks off after its head reached the client is never ended cleanly: the
 *    client's stream is reset (HTTP/1.1 closes the connection, HTTP/2 sends RST_STREAM, HTTP/3
 *    resets the stream), so a truncated body cannot look complete.
 *  - A request is retried on a fresh connection only when a reused pooled connection failed
 *    before any response byte, the method is idempotent and no body was sent; otherwise 502.
 *  - An upstream connection goes back to the pool only after a complete exchange with nothing
 *    left over; a client that leaves mid-response has its upstream connection closed. */
#ifndef BST_PROXY_HANDLER_H
#define BST_PROXY_HANDLER_H

#include "http/stream.h"

extern const bst_handler_ops bst_proxy_handler;

/* ---- forward_headers.c ---- */

/* The request fields sent upstream: the client's minus hop-by-hop and Connection-listed ones
 * (forwarding fields can not be removed that way), cookies of HTTP/2 and HTTP/3 joined into
 * one, Early-Data for 0-RTT, and X-Forwarded-* or Forwarded built from what the connection
 * proves. 0, or -1 when out of memory. *host is the Host to send. */
int bst_proxy_req_headers(bst_stream *s, bst_headers *out, bst_str *host);
/* The response fields for the client: the upstream's minus hop-by-hop, framing, Date and Server
 * (the protocol writes its own), Connection-listed and proxy_hide_header ones. */
int bst_proxy_resp_headers(const bst_stream *s, const bst_headers *in, bst_headers *out);
/* True when ip lies in one of the bst_cidr items of list. */
bool bst_proxy_cidr_match(const bst_cfg_list *list, const bst_ip *ip);

/* ---- real_ip.c ---- */

/* `real_ip_header` from a peer in `real_ip_from`: replaces the stream's peer address with the
 * address the header names (the rightmost one not itself in real_ip_from). */
void bst_proxy_real_ip(bst_stream *s);

#endif

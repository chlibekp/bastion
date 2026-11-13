/* Tunnels through the proxy (WebSocket over HTTP/1.1, and over HTTP/2 by RFC 8441 extended CONNECT
 * translated to an HTTP/1.1 Upgrade; RFC 9220 over HTTP/3 is not implemented). A tunnel starts only when the client asked
 * for a valid WebSocket upgrade AND the upstream answered 101 to the upgrade we sent: any other
 * answer is relayed as a normal response and the client's connection stays HTTP, so an upstream
 * cannot leave a raw tunnel open behind a refused upgrade (the known WebSocket smuggling
 * pattern). An upstream 101 to a request that did not ask for one is a malformed response (502).
 *
 * Once open, frames are relayed as opaque bytes in both directions with the proxy's usual credit
 * (a slow reader slows the writer, memory stays bounded). Either side ending its direction is
 * passed on as a half-close; the other then has tunnel_drain_timeout to finish. The tunnel also
 * closes after tunnel_idle_timeout without a byte, or tunnel_max_duration in all. The relay
 * copies through user space rather than splice: one path serves TLS and plain ends alike. */
#ifndef BST_PROXY_TUNNEL_H
#define BST_PROXY_TUNNEL_H

#include "http/stream.h"

#include <stdbool.h>

/* The request is a WebSocket upgrade the proxy may pass on: HTTP/1.1 GET with Upgrade: websocket,
 * Connection: upgrade, a Sec-WebSocket-Key of 16 base64-encoded bytes and version 13. */
bool bst_tunnel_ws_request(const bst_stream *s);
/* Extended CONNECT (RFC 8441 over HTTP/2, RFC 9220 over HTTP/3) carries no key: the proxy makes
 * one for the HTTP/1.1 Upgrade it sends (16 CSPRNG bytes in base64, NUL-terminated), and checks
 * the upstream's Sec-WebSocket-Accept against it. 0, or -1 when no random bytes came. */
int bst_tunnel_make_key(char out[32]);
bool bst_tunnel_accept_ok(const char *key, bst_str accept);
/* A tunnel slot of this worker under max (0 = none): false when full. */
bool bst_tunnel_acquire(unsigned max);
void bst_tunnel_release(void);
unsigned bst_tunnel_count(void);

#endif

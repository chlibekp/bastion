/* The PROXY protocol (HAProxy, versions 1 and 2): a load balancer in front names the client in a
 * header that precedes everything else on the connection, before a TLS ClientHello or a request.
 *
 * Accepting: a `listen ... proxy_protocol` socket reads the header first, but only from a peer in
 * `proxy_protocol_from`; anyone else is closed, and so is a connection whose header is missing,
 * malformed, or not complete within `proxy_protocol_timeout`. The header is read byte-exactly
 * (never past its end), so what follows it reaches TLS or HTTP untouched.
 *
 * Sending: `send_proxy_protocol v1|v2` in an upstream block writes a header naming the client
 * ($remote_addr) and the address it connected to on every new upstream connection, before TLS. */
#ifndef BST_PROXY_PROXYPROTO_H
#define BST_PROXY_PROXYPROTO_H

#include "core/addr.h"
#include "io/loop.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_PP_V1_MAX 107u   /* longest v1 line, CRLF included (the specification's bound) */
#define BST_PP_MAX 4096u     /* longest v2 header accepted, TLVs included */
#define BST_PP_V2_OUT_MAX 52u /* longest v2 header bst_pp_write_v2 writes (TCP6) */

typedef struct bst_pp_info {
	uint8_t version; /* 1 or 2 */
	bool local;	 /* v2 LOCAL: the balancer's own connection (a health check), no client */
	bool has_addr;	 /* src and dst are valid: TCP over IPv4 or IPv6 */
	bst_sockaddr src, dst;
	size_t len; /* bytes of the header */
} bst_pp_info;

/* Parses a header at the start of p[0..n). Returns its length (> 0) when complete, 0 when the
 * bytes so far are a valid beginning and more are needed, -1 when malformed (a bad signature, a
 * v1 line longer than BST_PP_V1_MAX, a v2 length too short for its addresses or above
 * BST_PP_MAX, an unknown command or family). */
int bst_pp_parse(const uint8_t *p, size_t n, bst_pp_info *out);

/* How many more bytes may be read after p[0..n) without reading past the end of the header
 * (at least 1 while incomplete). */
size_t bst_pp_want(const uint8_t *p, size_t n);

/* Writes a header for a connection from src to dst; NULL or an address of another family that
 * can not be mapped gives `PROXY UNKNOWN` (v1) or a PROXY command with no address (v2). Returns
 * the length, or 0 when cap is too small. */
size_t bst_pp_write_v1(const bst_sockaddr *src, const bst_sockaddr *dst, char *buf, size_t cap);
size_t bst_pp_write_v2(const bst_sockaddr *src, const bst_sockaddr *dst, uint8_t *buf, size_t cap);

/* Reads the header from the accepted fd on the loop. cb runs once, never from inside this call:
 * with the header (fd still open, positioned just after it, ownership back to the caller) or
 * with info NULL (fd already closed: missing, malformed, peer closed, or timeout_ms passed).
 * -1 when the read could not even start: fd is then closed and cb never runs. */
typedef void (*bst_pp_ready_cb)(void *ud, int fd, const bst_pp_info *info);
int bst_pp_accept(bst_loop *l, int fd, uint64_t timeout_ms, bst_pp_ready_cb cb, void *ud);

#endif

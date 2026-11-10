/* HTTP/1.1 request body decoder (RFC 9112 section 6 and 7.1): Content-Length and chunked, as a
 * byte-level state machine, so what it makes of the bytes never depends on how reads split them.
 * Decoded data leaves as segments of the input buffer itself (no copy); only a trailer section is
 * copied, into the arena, up to client_max_trailer_size. Strict: a chunk size takes only hex
 * digits (no space before the extension), line ends are CRLF, and any malformation is a 400
 * after which the connection is closed. */
#ifndef BST_HTTP_H1_BODY_H
#define BST_HTTP_H1_BODY_H

#include "core/arena.h"
#include "core/buf.h"
#include "core/chain.h"
#include "http/headers.h"
#include "http/semantics.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bst_h1_body_cfg {
	uint64_t max_body;	  /* client_max_body_size, 0 = unlimited: more is 413 */
	uint32_t chunk_ext_limit; /* chunk_ext_limit: bytes of extensions on one chunk */
	uint32_t max_trailer;	  /* client_max_trailer_size: bytes of trailer section, else 431 */
} bst_h1_body_cfg;

typedef enum bst_h1_body_kind {
	BST_H1_BODY_MORE, /* all input consumed, call again with the next read */
	BST_H1_BODY_DONE, /* the message ended; *off is the first byte after it */
	BST_H1_BODY_ERROR,
} bst_h1_body_kind;

typedef struct bst_h1_body {
	bst_framing framing;
	bst_h1_body_cfg cfg;
	bst_arena *arena;
	uint8_t st;
	int err;
	uint64_t remaining; /* bytes left of the Content-Length, or of the current chunk */
	uint64_t chunk;	    /* chunk size being read */
	uint64_t total;	    /* decoded bytes so far */
	uint32_t digits, ext_len, tlen, tcap;
	char *tbuf; /* the trailer section so far */
} bst_h1_body;

/* arena holds the trailer section; it must outlive the request. */
void bst_h1_body_init(bst_h1_body *b, bst_framing framing, const bst_h1_body_cfg *cfg,
		      bst_arena *arena);

/* Feeds in[*off .. in->len). Decoded data is appended to out as segments of in (the chain takes
 * its own references). Trailers that survive the filter (below) are added to trailers, which
 * may be NULL to drop them all. *off moves past what was used. On ERROR *status is 400, 413
 * (more than max_body) or 431 (trailers over the limit), and the decoder stays in error. A
 * trailer field is dropped when it can not safely be a trailer (RFC 9110 section 6.5.1): framing
 * (Content-Length, Transfer-Encoding, TE, Trailer), routing (Host), request modifiers
 * (Expect, Max-Forwards, Range, conditionals, Cache-Control, Pragma), authentication
 * (Authorization, Proxy-Authorization, Cookie, Set-Cookie) and how-to-process fields
 * (Content-Type, Content-Encoding, Content-Range, Content-Length). */
bst_h1_body_kind bst_h1_body_feed(bst_h1_body *b, bst_buf *in, size_t *off, bst_chain *out,
				  bst_headers *trailers, int *status);

/* True for a header name that may not appear as a trailer. */
bool bst_h1_trailer_forbidden(bst_str name);

#endif

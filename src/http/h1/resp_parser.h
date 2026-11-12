/* HTTP/1.1 response head parser and response framing (RFC 9112 sections 4, 5 and 6.3), for the
 * proxy's upstream side. The upstream is not trusted any more than a client: the status line and
 * every field are checked byte by byte (CRLF line ends only, no obsolete folding, no control
 * bytes, token names), so nothing an upstream sends can split a response or inject a header into
 * what the client gets. Any violation is an error the proxy answers with 502.
 *
 * Like the request parser, the caller owns one contiguous buffer holding the head so far and calls
 * again with it grown; the parser keeps offsets. On DONE the head is copied into the arena and the
 * result points into the copy. */
#ifndef BST_HTTP_H1_RESP_PARSER_H
#define BST_HTTP_H1_RESP_PARSER_H

#include "core/arena.h"
#include "http/h1/parser.h"
#include "http/headers.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bst_h1_resp_head {
	int status;
	uint8_t version_minor; /* HTTP/1.0 or HTTP/1.1 */
	bst_str reason;
	bst_headers headers;
} bst_h1_resp_head;

typedef struct bst_h1_resp_parser {
	bst_arena *arena;
	size_t scanned; /* bytes already searched for the end of the head */
} bst_h1_resp_parser;

void bst_h1_resp_parser_init(bst_h1_resp_parser *p, bst_arena *arena);
/* DONE fills out and consumed; ERROR (status 502) on a malformed head or one longer than
 * max_head; NEED_MORE otherwise. */
bst_h1_result bst_h1_parse_resp_head(bst_h1_resp_parser *p, const char *buf, size_t len,
				     size_t max_head, bst_h1_resp_head *out);

/* How the response body is delimited (RFC 9112 section 6.3). */
typedef enum bst_resp_body {
	BST_RESP_BODY_NONE,    /* HEAD, 1xx, 204, 304 */
	BST_RESP_BODY_LENGTH,
	BST_RESP_BODY_CHUNKED,
	BST_RESP_BODY_CLOSE,   /* read until the upstream closes */
} bst_resp_body;

typedef struct bst_h1_resp_framing {
	bst_resp_body kind;
	uint64_t length;
	bool keepalive; /* the connection may carry another request afterwards */
} bst_h1_resp_framing;

/* 0, or -1 for a response that may not be forwarded: Content-Length together with
 * Transfer-Encoding, differing or malformed Content-Length values, chunked that is not the last
 * coding or appears twice, Transfer-Encoding in an HTTP/1.0 response. head_request: the request
 * was HEAD (no body, whatever the fields say). */
int bst_h1_resp_framing_of(const bst_h1_resp_head *h, bool head_request, bst_h1_resp_framing *out);

/* True when a comma-separated Connection header in h lists name (any case). */
bool bst_h1_connection_lists(const bst_headers *h, bst_str name);

#endif

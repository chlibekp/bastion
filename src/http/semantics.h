/* Request semantics every protocol shares (RFC 9110): which host a request is for, whether the
 * connection may stay open, what the client expects, and which methods are served. HTTP/1.1
 * adds message framing on top (h1/framing.c); HTTP/2 and HTTP/3 call the same
 * bst_validate_request_semantics after mapping their pseudo-headers into a bst_req_head. */
#ifndef BST_HTTP_SEMANTICS_H
#define BST_HTTP_SEMANTICS_H

#include "http/http.h"

/* How a request's body is delimited (RFC 9112 section 6). */
typedef enum bst_framing_kind {
	BST_FRAMING_NONE,
	BST_FRAMING_LENGTH,
	BST_FRAMING_CHUNKED,
} bst_framing_kind;

typedef struct bst_framing {
	bst_framing_kind kind;
	uint64_t length; /* LENGTH: bytes */
} bst_framing;

/* The request as handlers see it: the head plus what the semantics layer derived. */
typedef struct bst_req {
	bst_req_head head;
	bst_str host;	    /* the authority it is for: the absolute-form target's, else Host */
	bst_framing framing;
	bool keepalive;	    /* the connection may carry another request (HTTP/1.x only) */
	bool expect_continue; /* Expect: 100-continue */
} bst_req;

/* Methods the server answers with 405's Allow header. */
#define BST_ALLOWED_METHODS "GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH"

/* host[:port] or [v6]:port with the characters RFC 3986 allows (no userinfo); need_port makes
 * the port mandatory (CONNECT). */
bool bst_valid_authority(bst_str a, bool need_port);

/* 0 when the request is acceptable, else the status to refuse it with: 400 for a missing,
 * repeated or malformed Host (an HTTP/1.1 request needs exactly one; an absolute-form target
 * wins over a Host that disagrees, RFC 9112 section 3.2.2) or a malformed Connection list, 417
 * for an expectation other than 100-continue, 405 for TRACE and CONNECT (with
 * BST_ALLOWED_METHODS) and 501 for a method Bastion does not know. Fills host, keepalive and
 * expect_continue; r->framing is the caller's. */
int bst_validate_request_semantics(bst_req *r);

/* HTTP/1.1 framing of a request head (h1/framing.c): NONE, LENGTH(n) or CHUNKED, or *status
 * set to 400 or 501 with kind NONE. Always strict: Content-Length with Transfer-Encoding, a
 * repeated or listed or non-decimal Content-Length, chunked not the last coding, and
 * Transfer-Encoding in an HTTP/1.0 request are refused, and there is no switch to relax it. */
bst_framing bst_h1_message_framing(const bst_req_head *h, int *status);

#endif

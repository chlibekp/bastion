/* Validation of a request that arrives as a list of decoded fields with pseudo-header fields
 * (:method, :scheme, :authority, :path, :protocol), shared by HTTP/2 (RFC 9113 section 8) and, in
 * Phase 8, HTTP/3 (RFC 9114 section 4.3). It turns the list into a bst_req_head, and refuses
 * everything that would make the request mean something different to a later hop: this is the
 * only place where "what an HTTP/2 client sent" becomes "what an HTTP/1.1 upstream could be
 * told" (Phase 9), so nothing that could carry a line break, a smuggled framing header or an
 * ambiguous host passes it. */
#ifndef BST_HTTP_VALIDATE_PSEUDO_H
#define BST_HTTP_VALIDATE_PSEUDO_H

#include "core/arena.h"
#include "http/http.h"
#include "http/semantics.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum bst_pseudo_rc {
	BST_PSEUDO_OK = 0,
	BST_PSEUDO_MALFORMED,   /* RFC 9113 section 8.1.1: a stream error of type PROTOCOL_ERROR */
	BST_PSEUDO_BAD_REQUEST, /* well-formed but unacceptable (Host and :authority disagree): 400 */
} bst_pseudo_rc;

typedef struct bst_pseudo_opts {
	bool end_stream;	  /* the header block ended the request: there is no body */
	bool allow_protocol;	  /* :protocol may appear (RFC 8441: the server advertised it) */
} bst_pseudo_opts;

typedef struct bst_pseudo_result {
	bst_str protocol;     /* :protocol of an extended CONNECT, empty otherwise */
	bool has_length;      /* a Content-Length was sent ... */
	uint64_t length;      /* ... and said this */
} bst_pseudo_result;

/* in: the fields as decoded (names lower-case, pseudo-header fields first). out->headers must be
 * initialised on the arena: regular fields are appended to it (cookie fields joined into one,
 * a single Host made from :authority), everything else of out is filled. */
bst_pseudo_rc bst_validate_pseudo_request(const bst_headers *in, bst_arena *arena, bst_req_head *out,
					  const bst_pseudo_opts *o, bst_pseudo_result *res);

/* A trailer section: no pseudo-header fields, and the rules for names and values. */
bool bst_validate_trailer_fields(const bst_headers *in);

/* One field name or value on its own (used by the response side too). */
bool bst_pseudo_name_ok(bst_str name);   /* lower-case token, a leading ':' marks a pseudo-header */
bool bst_pseudo_value_ok(bst_str value); /* no NUL, CR, LF or other control, no edge whitespace */

#endif

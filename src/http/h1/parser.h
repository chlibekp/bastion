/* HTTP/1.1 request head parser (RFC 9112 sections 2 to 5): a byte-at-a-time state machine, so
 * its answer depends on the bytes alone and never on how they were split across reads, and it
 * resumes where it stopped without rescanning. Inner loops over a run of plain bytes use the
 * vector scans of h1/scan.h.
 *
 * The caller owns one contiguous buffer holding the head so far, from its first byte, and calls
 * again with the same buffer grown (it may move: the parser keeps offsets, not pointers). The
 * parser never keeps the buffer past a call. On DONE the head is copied into the arena given
 * at init, and every bst_str of the result points into that copy, so the caller may reuse or
 * shift its buffer at once. Strict by design: one space between the parts of the request
 * line, no whitespace before a header colon, no obsolete line folding, no control bytes, and a
 * bare LF only with `http1_allow_bare_lf on`. */
#ifndef BST_HTTP_H1_PARSER_H
#define BST_HTTP_H1_PARSER_H

#include "core/arena.h"
#include "http/http.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_H1_MAX_LEADING_EMPTY 1 /* RFC 9112 section 2.2: ignore at least one empty line */
#define BST_H1_MAX_METHOD 32	   /* a longer method is answered 501 */

typedef struct bst_h1_limits {
	size_t max_uri;	    /* request-target bytes: more is 414 */
	size_t max_head;    /* request line and headers in all: more is 431 */
	size_t max_headers; /* header lines: more is 431 */
	bool allow_bare_lf; /* `http1_allow_bare_lf` */
} bst_h1_limits;

typedef enum bst_h1_kind {
	BST_H1_NEED_MORE,
	BST_H1_DONE,
	BST_H1_ERROR,
} bst_h1_kind;

typedef struct bst_h1_result {
	bst_h1_kind kind;
	int status;      /* ERROR: the response status (400, 414, 431, 501, 505) */
	size_t consumed; /* DONE: bytes of the buffer the head took, the final CRLF included */
} bst_h1_result;

typedef struct bst_h1_hent {
	uint32_t name_off, name_len, val_off, val_len;
} bst_h1_hent;

typedef struct bst_h1_parser {
	bst_arena *arena;
	uint8_t st, leading, ver_i, major, minor;
	int err;
	size_t pos; /* the next byte to look at: everything before it is validated */
	uint32_t m_off, m_len, t_off, t_len, n_off, n_len, v_off;
	bst_h1_hent *ents;
	uint32_t nent, cap;
} bst_h1_parser;

/* Starts a head. The arena holds the result and the parser's entry list; it must outlive the
 * request. */
void bst_h1_parser_init(bst_h1_parser *p, bst_arena *arena);

/* Feeds the head buffer, grown since the last call (len never shrinks). DONE fills out; ERROR
 * is sticky; NEED_MORE means call again with more bytes. len above limits->max_head is fine:
 * only the first max_head bytes are looked at. */
bst_h1_result bst_h1_parse_head(bst_h1_parser *p, const char *buf, size_t len,
				const bst_h1_limits *limits, bst_req_head *out);

#endif

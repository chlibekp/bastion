/* The HTTP/1.1 client side of the proxy: writes a request head and reads a response from an
 * upstream connection, byte-split independent. The head is always written anew from parsed
 * fields (never the client's bytes), and the response is read with the strict parser of
 * http/h1/resp_parser.h, so what reaches either side has been parsed and regenerated. */
#ifndef BST_PROXY_CLIENT_H1_H
#define BST_PROXY_CLIENT_H1_H

#include "core/arena.h"
#include "core/buf.h"
#include "core/chain.h"
#include "http/h1/body.h"
#include "http/h1/resp_parser.h"

#include <stdbool.h>
#include <stddef.h>

/* ---- request head ---- */

typedef struct bst_h1_req_out {
	bst_str method;
	bst_str target; /* origin form: path and query, as sent upstream */
	bst_str host;
	const bst_headers *headers; /* already filtered: no hop-by-hop or framing fields */
	bool chunked;		    /* the body is sent chunked (length unknown) */
	bool has_length;	    /* Content-Length: length */
	uint64_t length;
} bst_h1_req_out;

/* Serializes the head into a new buffer. NULL when out of memory, or when a name is not a token
 * or a value holds a byte that could split the head (the request is then refused, never sent). */
bst_buf *bst_h1_req_head(const bst_h1_req_out *r);

/* ---- response reader ---- */

typedef enum bst_upc_ev {
	BST_UPC_MORE,	 /* everything consumed, feed the next read */
	BST_UPC_INTERIM, /* a 1xx head is in head; call feed again for the rest */
	BST_UPC_HEAD,	 /* the final head is in head and framing; call feed again */
	BST_UPC_BODY,	 /* body bytes were added to the chain; call feed again for the rest */
	BST_UPC_DONE,	 /* the response ended; *off is the first byte after it */
	BST_UPC_ERROR,	 /* a malformed response: 502 before the head, an abort after */
} bst_upc_ev;

typedef struct bst_h1_client {
	bst_arena *arena;
	size_t max_head;
	bool head_req;
	int st;
	char *hbuf; /* the head so far, malloc'd */
	size_t hlen, hcap;
	bst_h1_resp_parser p;
	bst_h1_resp_head head;
	bst_h1_resp_framing fr;
	bst_h1_body body;
	bst_h1_body_cfg bcfg;
	bst_headers trailers;
	uint64_t body_bytes;
	bool got_bytes; /* any byte of a response arrived */
} bst_h1_client;

void bst_h1_client_init(bst_h1_client *c, bst_arena *arena, size_t max_head, bool head_req,
			const bst_h1_body_cfg *bcfg);
void bst_h1_client_free(bst_h1_client *c);
/* Feeds in[*off .. in->len). Body bytes go to out as segments of in. */
bst_upc_ev bst_h1_client_feed(bst_h1_client *c, bst_buf *in, size_t *off, bst_chain *out);
/* The upstream closed: DONE for a close-delimited body, else ERROR (a truncated response). */
bst_upc_ev bst_h1_client_eof(bst_h1_client *c);
/* The response has a body length the client can be told up front: Content-Length or none. */
bool bst_h1_client_reusable(const bst_h1_client *c);

#endif

/* HTTP/1.1 connection (RFC 9112): reads requests, runs each as a bst_stream, writes responses in
 * request order. One connection is one loop-thread object; everything here runs on the loop.
 *
 * Pipelining. Each request becomes a stream as soon as its head is parsed, and its handler starts
 * at once, so handlers of pipelined requests overlap. Only the stream at the head of the queue
 * writes to the socket; the others keep their response in memory (one send_body at a time, whose
 * done callback waits for the stream's turn), which is the back-pressure on their handlers. At
 * most http1_max_pipeline streams are open: beyond that the connection stops reading. */
#ifndef BST_HTTP_H1_CONN_H
#define BST_HTTP_H1_CONN_H

#include "http/stream.h"
#include "http/transport.h"
#include "proc/worker.h"

/* The worker's connection hook (bst_worker_on_conn): wraps fd in the plain transport and starts
 * the connection for the listener's servers. Closes fd when it cannot. */
void bst_h1_on_conn(bst_worker *w, int fd, const bst_sockaddr *peer, const bst_cfg_listen *l);
/* The worker's drain hook: closes idle connections, and ends the others after their response. */
void bst_h1_drain(bst_worker *w);

/* Starts HTTP/1.1 on a transport it then owns. set must outlive the connection. 0, or -1 with
 * the transport closed. */
int bst_conn_h1_start(bst_worker *w, bst_transport *t, const bst_cfg_server_set *set);

/* ---- serializer (serialize.c) ---- */

typedef struct bst_h1_head_opts {
	bool chunked;      /* Transfer-Encoding: chunked */
	bool close;        /* Connection: close */
	bool keepalive;    /* Connection: keep-alive (an HTTP/1.0 client that asked for it) */
	bool omit_length;  /* no Content-Length (1xx, 204, 304, HEAD of an unknown length) */
	bool server_tokens;
} bst_h1_head_opts;

/* "HTTP/1.1 <status> <reason>\r\n" and the headers, ended by a blank line, in a fresh buffer
 * (len set). Framing and connection headers of h->headers are dropped; Date and Server are
 * added when the handler gave none. NULL on exhaustion or when a header name or value could
 * split the message (not a token, or a CR, LF or NUL in the value). */
bst_buf *bst_h1_serialize_head(const bst_resp_head *h, const bst_h1_head_opts *o);
/* The status line and headers of an interim response (100, 103). */
bst_buf *bst_h1_serialize_interim(int status, const bst_headers *h);
/* "<hex>\r\n" for a chunk of n bytes; returns its length. */
size_t bst_h1_chunk_prefix(char out[24], size_t n);

#endif

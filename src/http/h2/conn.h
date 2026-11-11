/* HTTP/2 connection (RFC 9113): reads frames, runs every request as a bst_stream, and writes the
 * responses in the order the scheduler (sched.c) picks. One connection is one loop-thread object;
 * everything here runs on the loop and never blocks.
 *
 * Layout. conn.c holds the lifecycle, the read path and the frame handlers; stream.c the stream
 * table and teardown; flow.c flow control; sched.c the RFC 9218 scheduler and the write pump;
 * bridge.c the bst_stream_ops and the mapping of requests to the HTTP semantics layer; guard.c the
 * abuse budgets. frame.c and hpack.c are pure libraries. */
#ifndef BST_HTTP_H2_CONN_H
#define BST_HTTP_H2_CONN_H

#include "http/stream.h"
#include "http/transport.h"
#include "proc/worker.h"

#include <stddef.h>

/* Starts HTTP/2 on a transport it then owns (after ALPN chose h2, or on a cleartext listener whose
 * client sent the preface). set must outlive the connection; peer (may be NULL) is copied. prefix,
 * when not NULL, are bytes already read from the transport (the start of the client preface), and
 * are processed first. 0, or -1 with the transport closed. */
int bst_conn_h2_start(bst_worker *w, bst_transport *t, const bst_listener_set *set,
		      const bst_sockaddr *peer, const void *prefix, size_t prefix_len, bool syn_data);
/* The same on a loop, with no worker behind it (w may be NULL: no connection count, no memory
 * budget). For tests that drive a connection over a transport of their own. */
int bst_conn_h2_start_loop(bst_loop *loop, bst_worker *w, bst_transport *t, const bst_listener_set *set,
			   const bst_sockaddr *peer, const void *prefix, size_t prefix_len, bool syn_data);

/* A cleartext connection on a `listen ... h2c` address (h2c.c): reads until it knows whether the
 * client sent the HTTP/2 preface (prior knowledge, RFC 9113 section 3.3) or something else, then
 * starts HTTP/2 or HTTP/1.1 with the bytes read so far. `Upgrade: h2c` is not honoured (RFC 9113
 * removed it). Takes ownership of t; a client that sends nothing is cut off at
 * client_header_timeout. */
void bst_h2c_sniff(bst_worker *w, bst_transport *t, const bst_listener_set *set, const bst_sockaddr *peer,
		   bool syn_data);

/* The worker's drain hook for HTTP/2 connections: a graceful two-phase GOAWAY, then the connection
 * ends once its streams have finished. */
void bst_h2_drain(bst_worker *w);

/* The 24-byte client connection preface (RFC 9113 section 3.4). */
#define BST_H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define BST_H2_PREFACE_LEN 24u

#endif

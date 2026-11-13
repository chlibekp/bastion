/* The HTTP/2 client side of the proxy (`protocol http2` in an `upstream`): the Phase 7 frame codec,
 * HPACK and flow-control rules used in client mode. Each worker keeps its own connections per
 * peer address and multiplexes requests over them as streams.
 *
 * Connections. A stream goes to a connection to the same peer that has room for it under the
 * smaller of the peer's SETTINGS_MAX_CONCURRENT_STREAMS and `max_upstream_h2_streams`; only when
 * every one is full is a new connection opened. Streams beyond the peer's limit wait on their
 * connection until one ends, so the peer's limit is never exceeded. A GOAWAY drains the
 * connection: streams the peer says it never processed (ids above its last-stream-id, or a
 * REFUSED_STREAM reset) are reported as refused, which is safe to retry on another connection;
 * the others finish, and the connection closes when the last one ends. An idle connection closes
 * after the upstream's keepalive_timeout.
 *
 * Flow control. The peer's windows are honoured for everything sent. What is received is bounded
 * per stream: the stream's receive window is only reopened as the caller reports the bytes
 * consumed (bst_h2us_consumed), so a slow client slows its upstream stream and memory stays
 * bounded; the connection window is reopened as bytes arrive, so one slow stream never blocks
 * the others.
 *
 * Validation. Responses are decoded with the bounded HPACK decoder (a decoded block is limited to
 * 64 KiB, the SETTINGS_MAX_HEADER_LIST_SIZE we advertise) and checked: exactly one :status first and no other
 * pseudo-field, no connection-specific field, trailers only with END_STREAM and without
 * pseudo-fields. Anything else resets the stream (or closes the connection for a connection
 * error), and the caller sees an error. */
#ifndef BST_PROXY_CLIENT_H2_H
#define BST_PROXY_CLIENT_H2_H

#include "core/addr.h"
#include "core/chain.h"
#include "http/headers.h"
#include "io/loop.h"
#include "proxy/upstream.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct bst_h2us bst_h2us;

/* Kinds of stream failure given to on_error. */
enum {
	BST_H2US_FAILED = 0,  /* after the request may have reached the upstream */
	BST_H2US_CONNECT = 1, /* the connection could not be made: nothing was sent */
	BST_H2US_REFUSED = 2, /* the peer did not process the stream (GOAWAY, REFUSED_STREAM) */
};

typedef struct bst_h2us_ops {
	/* The final response head (1xx heads are skipped). end: no body follows. */
	void (*on_head)(void *ud, int status, const bst_headers *h, bool end);
	/* Body bytes (data is the callee's to take); end: the response is complete. */
	void (*on_data)(void *ud, bst_chain *data, bool end);
	/* Trailers: the response is complete after them. */
	void (*on_trailers)(void *ud, const bst_headers *t);
	/* The stream failed: err a negative errno, kind one of BST_H2US_*. Nothing follows. */
	void (*on_error)(void *ud, int err, int kind);
	/* Everything given to bst_h2us_send was written: the caller may send more. */
	void (*on_sent)(void *ud);
} bst_h2us_ops;

/* Opens a stream for a request. req holds the pseudo-fields (:method, :scheme, :authority, :path)
 * first, then the regular fields (no connection-specific ones). body: request body bytes follow
 * through bst_h2us_send, else the HEADERS frame ends the stream. Callbacks never run from inside
 * this call. NULL when out of memory. */
bst_h2us *bst_h2us_open(bst_loop *l, const bst_cfg_upstream *u, const bst_peer *peer,
			const bst_sockaddr *addr, const bst_headers *req, bool body,
			const bst_h2us_ops *ops, void *ud);
/* Queues request body bytes (data is emptied); end: the last of them. 0, or -1 when the stream is
 * no longer open (the bytes are dropped). on_sent follows once they are written. */
int bst_h2us_send(bst_h2us *st, bst_chain *data, bool end);
/* The caller passed on n received body bytes: the peer may send that much more. */
void bst_h2us_consumed(bst_h2us *st, size_t n);
/* The caller is done with the stream: an open stream is reset (CANCEL). No callback runs after
 * this, and st is gone. */
void bst_h2us_release(bst_h2us *st);

/* Connections of this worker to the upstream (open or opening). */
unsigned bst_h2up_conns(const bst_cfg_upstream *u);

#endif

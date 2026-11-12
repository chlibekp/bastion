/* bst_stream: the one boundary protocols and handlers meet at (architecture section 5). HTTP/1.1
 * (h1/conn.c), HTTP/2 and HTTP/3 implement bst_stream_ops; handlers implement bst_handler_ops
 * and talk to the stream only through the functions below, so a handler written once serves every
 * protocol.
 *
 * Rules every implementation keeps:
 *  - Backpressure. The done callback of send_body is the only signal to produce more data; a
 *    handler has at most one send_body outstanding. A request body arrives only as far as the
 *    credit given with read_body: nothing buffers without limit.
 *  - Teardown. bst_handler_ops.on_reset runs exactly once when the stream ends before the
 *    handler finished (the peer left, a deadline ran out, the protocol broke), and afterwards the
 *    handler must not touch the stream, whose memory is gone: no done callback of an
 *    outstanding send_body runs either. A handler that finishes the response (send_* with
 *    end_stream) gets no on_reset.
 *  - Lifetime. Everything in req and the arena lives until the stream is released, which is
 *    after the last callback of the handler. Handler state allocated from the stream arena
 *    needs no free; a timer or other external registration is cancelled in on_reset. */
#ifndef BST_HTTP_STREAM_H
#define BST_HTTP_STREAM_H

#include "config/compile.h"
#include "core/addr.h"
#include "core/arena.h"
#include "core/chain.h"
#include "http/http.h"
#include "http/semantics.h"
#include "io/net.h"
#include "route/location.h"
#include "route/regex.h"
#include "route/vhost.h"

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

typedef struct bst_worker bst_worker;
typedef struct bst_stream bst_stream;
typedef struct bst_filter bst_filter;

typedef struct bst_stream_ops { /* implemented by h1, h2, h3 */
	int (*send_head)(bst_stream *, const bst_resp_head *, bool end_stream);
	int (*send_interim)(bst_stream *, int status, const bst_headers *);
	int (*send_body)(bst_stream *, bst_chain *, bool end_stream, bst_done_cb, void *ud);
	int (*send_trailers)(bst_stream *, const bst_headers *);
	void (*read_body)(bst_stream *, size_t credit); /* grants request-body flow credit */
	void (*reset)(bst_stream *, bst_stream_err);
} bst_stream_ops;

typedef struct bst_handler_ops { /* implemented by handlers */
	void (*on_request)(bst_stream *);
	void (*on_body)(bst_stream *, bst_chain *, bool end_stream);
	void (*on_trailers)(bst_stream *, const bst_headers *);
	void (*on_reset)(bst_stream *, bst_stream_err);
} bst_handler_ops;

typedef struct bst_filter_ops { /* response filter chain (Phase 11) */
	int (*on_head)(bst_filter *, bst_resp_head *, bool end_stream);
	int (*on_body)(bst_filter *, bst_chain *, bool end_stream);
} bst_filter_ops;

struct bst_stream {
	const bst_stream_ops *ops; /* the protocol */
	void *proto;		   /* the protocol's own state for this stream */
	const bst_handler_ops *handler;
	void *hctx;
	bst_arena *arena; /* per request: reset when the stream is released */
	bst_slab *chain_slab; /* for the chains a handler builds: bst_chain_init(&c, s->chain_slab) */
	bst_req req;
	bst_sockaddr peer;	      /* the client; valid when has_peer */
	bool has_peer;
	bst_str request_id;	      /* made on first use by $request_id */
	bst_worker *worker;
	const struct bst_transport *transport; /* what the request arrived over: $scheme, $ssl_* */
	const bst_cfg_server *server; /* the virtual server the request matched */
	const bst_cfg_common *cfg;    /* its effective configuration: the location's, else the server's */
	/* Set by the router (route/router.c) before a handler runs. */
	const bst_cfg_location *loc;  /* the location it matched, NULL for the server's own */
	bst_str uri;		      /* the normalized path, NUL-terminated (route/uri.h) */
	bst_captures caps;	      /* groups of the regex that chose the location: $1..$9 */
	bool internal_ok;	      /* re-routed by try_files or error_page: `internal` locations answer */
	bool in_error_page;	      /* serving an error_page: an error from it is the default page */
	int status_override;	      /* the status an error_page response is sent with, 0 when none */
	unsigned reroutes;	      /* internal redirects so far, bounded by rewrite_max_cycles */
	bool uri_changed;	      /* a rewrite or reroute replaced the path: a proxy sends uri */
};

bst_arena *bst_stream_arena(bst_stream *s);
bst_req *bst_stream_req(bst_stream *s);
/* Installs the handler and calls its on_request. */
void bst_stream_set_handler(bst_stream *s, const bst_handler_ops *h, void *hctx);

/* Thin wrappers over the protocol's ops. 0, or -1 when the stream is gone or the response is
 * out of order (a second head, a body before the head). */
int bst_stream_send_head(bst_stream *s, const bst_resp_head *h, bool end_stream);
int bst_stream_send_interim(bst_stream *s, int status, const bst_headers *h);
/* Takes the segments of c (it is empty afterwards and may be reused at once); cb, when not NULL,
 * runs once they are written or the protocol has dropped them (HEAD), never before send_body
 * returns. */
int bst_stream_send_body(bst_stream *s, bst_chain *c, bool end_stream, bst_done_cb cb, void *ud);
int bst_stream_send_trailers(bst_stream *s, const bst_headers *h);
void bst_stream_read_body(bst_stream *s, size_t credit);

/* ---- errors (errors.c) ---- */

/* The reason phrase of a status, "Unknown" for one Bastion never sends. */
const char *bst_http_reason(int status);
/* Answers with a small HTML page for status (and a Retry-After or Allow header when the status
 * calls for it); the connection is closed afterwards for the statuses that mean the request
 * could not be read. The stream is complete after it. 0, or -1 on exhaustion. */
int bst_send_error(bst_stream *s, int status);
/* The same with one extra header, e.g. Allow on 405 or Location on a redirect. */
int bst_send_error_hdr(bst_stream *s, int status, bst_str name, bst_str value);

/* ---- Date (date.c) ---- */

#define BST_HTTP_DATE_LEN 29 /* "Sun, 06 Nov 1994 08:49:37 GMT" */
size_t bst_http_date_format(time_t t, char out[BST_HTTP_DATE_LEN + 1]);
/* The current time in that form, cached for the second: valid until the next call. */
bst_str bst_http_date(void);

/* The router (route/router.c): normalizes the path, picks the location and starts its handler.
 * Called once per request, after the head (and the semantics checks) passed. */
void bst_stream_dispatch(bst_stream *s);

/* Internal redirect: serves uri (a decoded path, as try_files and error_page give it) as if it had
 * been requested, through the router again. err_status is non-zero for an error_page: the response
 * keeps that status. Bounded by rewrite_max_cycles; past it the request is a 500. */
void bst_stream_reroute(bst_stream *s, bst_str uri, int err_status);

/* The built-in `return` handler (return.c). */
extern const bst_handler_ops bst_return_handler;

#endif

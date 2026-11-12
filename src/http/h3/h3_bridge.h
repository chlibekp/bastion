/* HTTP/3 (RFC 9114) over one QUIC connection: nghttp3 frames the streams, and every request stream
 * becomes a bst_stream served by the same HTTP semantics layer as HTTP/1.1 and HTTP/2
 * (validate_pseudo.c, semantics.c, the router). The QUIC side (quic.c) feeds stream data and
 * stream events in, and pulls what nghttp3 has to send out with nghttp3_conn_writev_stream from its
 * write loop.
 *
 * Request bodies arrive as far as the handler's read_body credit goes; the QUIC stream and
 * connection credit is given back to the client only for bytes the handler took, so a slow handler
 * holds the client back instead of buffering. Response bodies: memory segments are handed to
 * nghttp3 as they are, file segments are read into 64 KiB buffers on the loop thread (pread), and
 * at most BST_H3_STREAM_BUF bytes per stream are read ahead of what the client acknowledged. The
 * handler's send_body callback runs once its data is all staged within that bound, so a 1 GiB file
 * costs one window of memory, held back by the stream and connection credit the client gives.
 *
 * Callbacks into handlers never run inside nghttp3's own: send_body completions run from a 1 ms
 * timer, after which the connection writes. Everything runs on the worker's loop thread. */
#ifndef BST_HTTP_H3_BRIDGE_H
#define BST_HTTP_H3_BRIDGE_H

#include "config/compile.h"
#include "core/addr.h"
#include "http/transport.h"
#include "io/loop.h"
#include "route/vhost.h"

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <stdbool.h>
#include <stdint.h>

#define BST_H3_STREAM_BUF (512u * 1024u) /* response bytes read ahead per stream */

/* RFC 9114 section 8.1 error codes the bridge uses. */
#define BST_H3_NO_ERROR 0x100u
#define BST_H3_INTERNAL_ERROR 0x102u
#define BST_H3_REQUEST_REJECTED 0x10bu
#define BST_H3_REQUEST_CANCELLED 0x10cu
#define BST_H3_MESSAGE_ERROR 0x10eu

typedef struct bst_h3_conn bst_h3_conn;
typedef struct bst_worker bst_worker;

/* What the bridge needs of its QUIC connection. */
typedef struct bst_h3_env {
	ngtcp2_conn *q;
	bst_loop *loop;
	bst_worker *w;		    /* NULL: no memory budget */
	const bst_listener_set *set;
	const bst_cfg_quic *cfg;    /* the listener's default server's figures */
	bst_transport *t;	    /* TLS over QUIC (tls/conn.h), for $ssl_* and the SNI policy */
	bst_sockaddr peer;
	/* Something is ready to send: the connection writes (never called from inside a bridge
	 * function the QUIC side called; always from the bridge's own timer). */
	void (*write)(void *ud);
	/* A connection error: CONNECTION_CLOSE with this HTTP/3 code. */
	void (*fail)(void *ud, uint64_t h3_code);
	void *ud;
} bst_h3_env;

/* Opens the server's control and QPACK streams. NULL on exhaustion or when the client allows too
 * few unidirectional streams. */
bst_h3_conn *bst_h3_conn_new(const bst_h3_env *env);
/* Every live stream's handler is told on_reset (CANCEL); nothing is sent. */
void bst_h3_conn_free(bst_h3_conn *h);
nghttp3_conn *bst_h3_nghttp3(bst_h3_conn *h);

/* ---- from the QUIC connection (ngtcp2 callbacks) ---- */

/* Stream data. 0, or a negative nghttp3 error: the connection must close with
 * nghttp3_err_infer_quic_app_error_code of it. Gives QUIC credit back for every byte that is not
 * request body (body credit goes back as the handler takes it). */
int bst_h3_recv(bst_h3_conn *h, int64_t sid, const uint8_t *data, size_t len, bool fin);
int bst_h3_acked(bst_h3_conn *h, int64_t sid, uint64_t n);
/* Both directions of the stream are closed. app_code is the peer's or ours (H3_NO_ERROR when none). */
int bst_h3_stream_closed(bst_h3_conn *h, int64_t sid, uint64_t app_code);
/* The peer reset its sending side (RESET_STREAM) or asked us to stop sending (STOP_SENDING). */
int bst_h3_peer_reset(bst_h3_conn *h, int64_t sid);
int bst_h3_peer_stop_sending(bst_h3_conn *h, int64_t sid);
int bst_h3_max_streams(bst_h3_conn *h, uint64_t n);
int bst_h3_unblock(bst_h3_conn *h, int64_t sid);
/* The handshake completed: requests no longer count as early data. */
void bst_h3_handshake_done(bst_h3_conn *h);

/* Graceful stop: GOAWAY, then the connection is closed (H3_NO_ERROR) once its streams finished. */
void bst_h3_drain(bst_h3_conn *h);
/* True once a drained connection has no stream left. */
bool bst_h3_drained(const bst_h3_conn *h);

#endif

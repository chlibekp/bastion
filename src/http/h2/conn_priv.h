/* Private to the HTTP/2 connection: its two objects and the functions its files share. Nothing
 * outside src/http/h2 includes this. */
#ifndef BST_HTTP_H2_CONN_PRIV_H
#define BST_HTTP_H2_CONN_PRIV_H

#include "core/wheel.h"
#include "http/h2/conn.h"
#include "http/h2/frame.h"
#include "http/h2/guard.h"
#include "http/h2/hpack.h"

#include <stdlib.h>

#define H2_BUCKETS 64u	      /* hash buckets of the stream table */
#define H2_CLOSED_RING 64u    /* closed stream ids remembered, to tell a race from a violation */
#define H2_URGENCIES 8u	      /* RFC 9218 section 4.1: urgency 0 (most) to 7 (least) */
#define H2_DEFAULT_URGENCY 3u
#define H2_ARENA_CHUNK 4096u  /* a stream's arena grows by this much; also its share of the memory budget */

typedef struct h2c h2c;
typedef struct h2s h2s;

/* What a header block being assembled is for. */
enum { H2_HB_NEW, H2_HB_TRAILERS, H2_HB_DISCARD };

typedef enum h2_closed_how {
	H2_CL_NONE = 0,
	H2_CL_LOCAL_RST,  /* we reset it: frames racing the reset are ignored */
	H2_CL_REMOTE_RST, /* the peer reset it */
	H2_CL_ENDED,	  /* both directions ended */
} h2_closed_how;

struct h2s {
	bst_stream s; /* first: a bst_stream * is an h2s * */
	h2c *c;
	uint32_t id;
	h2s *hnext;		    /* bucket chain of the stream table */
	h2s *rnext, *rprev;	    /* the ready list of its urgency */
	h2s *wnext;		    /* the streams that contributed to the write in flight */
	h2s *dnext;		    /* the deferred release list */
	h2s *cnext;		    /* the list of streams whose send_body callback is due */
	bool in_cbq;
	bool remote_closed;	    /* END_STREAM received: the request is complete */
	bool local_closed;	    /* END_STREAM queued: the response is complete */
	bool dead;		    /* reset or finished: freed by the next h2c_reap */
	bool detached;		    /* the handler was told on_reset, or never had one */
	bool own;		    /* the connection answers on its own behalf: ops work though detached */
	bool in_ready, in_batch, in_reap;
	/* request */
	bst_chain in;		    /* body received, not yet given to the handler */
	bool reading;
	uint64_t credit;	    /* body bytes the handler asked for */
	int64_t recv_win;	    /* what the peer may still send on this stream */
	uint64_t recv_pending;	    /* bytes the handler took that the peer has not been credited for */
	bool has_cl;
	uint64_t cl, body_seen;
	bst_headers trailers;
	bool expect_sent, end_sent, rejected;
	/* response */
	int64_t send_win;	    /* what the peer lets us send on this stream (may be negative) */
	bst_chain out;		    /* body not yet written */
	bst_done_cb cb;		    /* the handler's outstanding send_body */
	void *cb_ud;
	bool head_sent, resp_done, end_queued, is_head, no_body, trailers_due;
	int64_t cl_left;	    /* Content-Length bytes still to send, -1 when not counting */
	bst_headers resp_trailers;
	uint8_t urgency;
	bool incremental;
	uint64_t stall_ms;	    /* since when it waits on the peer's window; 0 when it does not */
	size_t charged;
};

struct h2c {
	h2c *prev, *next;
	bst_worker *w;
	bst_loop *loop;
	bst_transport *t;
	const bst_listener_set *set;
	bst_sockaddr peer;
	bool has_peer;
	const bst_cfg_http *hc; /* connection-level figures: the listener's default server */
	const bst_cfg_h2 *cfg;
	bool syn_data, syn_checked;
	/* read */
	uint8_t *in;
	size_t in_len, in_cap;
	size_t preface_have;	/* bytes of the client preface matched so far */
	bool preface_ok, got_settings;
	bool recv_on;
	/* the peer's settings (RFC 9113 section 6.5.2) */
	uint32_t peer_max_frame;
	int64_t peer_initial_window;
	bool peer_connect_protocol;
	uint32_t enc_table_cap; /* what we let the encoder use: min(peer's, ours) */
	/* connection-level windows */
	int64_t send_win, recv_win;
	uint64_t recv_pending;
	/* streams */
	h2s *bucket[H2_BUCKETS];
	unsigned nstreams;	/* streams the peer opened that are not finished */
	uint32_t last_stream;	/* the highest stream id the peer has used */
	struct {
		uint32_t id;
		uint8_t how;
	} ring[H2_CLOSED_RING];
	unsigned closed_next;
	/* header compression and the header block being assembled */
	bst_hpack_dec dec;
	bst_hpack_enc enc;
	bst_arena *scratch;
	struct {
		bool active;
		uint32_t sid;
		bool end_stream;
		uint8_t mode;	/* H2_HB_* */
		uint8_t *buf;
		size_t len, cap;
		unsigned frames; /* CONTINUATION frames so far */
	} hb;
	/* write */
	bst_h2_wr ctl;		/* control frames and header blocks, in the order they were made */
	bst_chain wchain;
	bool writing;
	h2s *batch;		/* streams whose data is in the write in flight */
	h2s *cbq;		/* streams whose send_body callback is due (nothing left to write) */
	h2s *reapq;
	unsigned trailers_pending;
	bool stall_armed;
	/* scheduler */
	h2s *rhead[H2_URGENCIES], *rtail[H2_URGENCIES];
	/* lifecycle */
	bool settings_acked, goaway_sent, graceful, graceful_final, dying, closed, lingering, peer_goaway;
	uint32_t ping_token;
	bst_timer t_idle, t_settings, t_send, t_flush, t_stall, t_ling;
	bool flush_armed, partial_armed;
	uint64_t served;
	int depth;
	bst_h2_guard guard;
};

static inline void h2c_enter(h2c *c) { c->depth++; }
static inline void h2c_leave(h2c *c)
{
	if (--c->depth == 0 && c->closed)
		free(c);
}

/* frames.c: one parsed frame of the peer. */
void h2c_frame(h2c *c, const bst_h2_frame *f);
/* The partial-input deadline follows what is half received (conn.c). */
void h2c_update_partial(h2c *c);
bool h2c_charge(h2c *c, bst_h2_guard_kind kind);

/* conn.c */
void h2c_graceful(h2c *c);
void h2c_close(h2c *c);
/* A connection error: GOAWAY with the code, then the connection ends once it is written. */
void h2c_conn_error(h2c *c, uint32_t code);
/* A stream error: RST_STREAM on id, and the stream (when live) is torn down. */
void h2c_stream_error(h2c *c, uint32_t id, uint32_t code);
void h2c_update_recv(h2c *c);
void h2c_arm_idle(h2c *c);
/* Queues a frame writer's output into ctl; false (and the connection ends) on exhaustion. */
bool h2c_queue_ok(h2c *c, int rc);

/* Resets one live stream from our side: RST_STREAM(code) is queued and the stream ends, its
 * handler told why. */
void h2s_reset(h2s *s, uint32_t code, bst_stream_err why);
/* The connection's output has room or something is due: runs the pump, the callbacks and the
 * reaper soon (not before the caller returns). */
void h2c_cbq_push(h2s *s);
bst_slab *h2_slab(void);

/* stream.c */
h2s *h2s_new(h2c *c, uint32_t id);
h2s *h2s_find(h2c *c, uint32_t id);
void h2s_note_closed(h2c *c, uint32_t id, h2_closed_how how);
h2_closed_how h2s_closed_how(const h2c *c, uint32_t id);
/* Tells the handler (once) that the stream ended before it finished. */
void h2s_detach(h2s *s, bst_stream_err why);
/* Ends a stream now from the protocol's side: the handler is told, it leaves the scheduler and
 * the table, and its memory is freed at the next h2c_reap. how is what later frames for the id
 * mean. */
void h2s_kill(h2s *s, bst_stream_err why, h2_closed_how how);
/* Both directions are complete (or we reset the request side): ends a finished stream. */
void h2s_check_done(h2s *s);
void h2c_reap(h2c *c);
void h2c_free_streams(h2c *c);
void h2s_each(h2c *c, void (*fn)(h2s *, void *), void *arg);

/* flow.c */
/* The handler took n bytes of request body (or they were dropped): credit goes back to the peer
 * by the receive policy. s may be NULL (bytes of a stream that no longer exists). */
void h2_recv_consumed(h2c *c, h2s *s, size_t n);
/* A DATA frame of length bytes (padding included) arrived. Returns 0, or the error code with
 * *stream set to the stream to reset (0: the whole connection). */
uint32_t h2_recv_account(h2c *c, h2s *s, uint32_t length, bool *stream_err);
/* WINDOW_UPDATE; s NULL for the connection. Returns 0 or the error code (stream_err as above). */
uint32_t h2_send_window_update(h2c *c, h2s *s, uint32_t inc, bool *stream_err);
/* SETTINGS_INITIAL_WINDOW_SIZE changed: 0, or FLOW_CONTROL_ERROR. */
uint32_t h2_set_initial_window(h2c *c, int64_t v);

/* sched.c */
void h2_sched_update(h2s *s);	/* put on, or take off, the ready lists according to its state */
void h2_sched_remove(h2s *s);
void h2c_pump(h2c *c);
void h2c_arm_flush(h2c *c);
void h2c_on_stall_timer(h2c *c);
/* Applies a Priority field value ("u=3, i") to a stream. */
void h2_set_priority(h2s *s, const char *v, size_t n);

/* bridge.c */
extern const bst_stream_ops bst_h2_ops;
/* A complete request header block (decoded into in, on the stream's arena) for a stream just
 * created: validates it, applies the connection policies and starts the handler, or answers the
 * refusal itself. */
void h2_request_start(h2c *c, h2s *s, const bst_headers *in, bool end_stream);
/* A trailer section (decoded into in) ending a request: false when it is malformed. */
bool h2_request_trailers(h2c *c, h2s *s, const bst_headers *in);
/* A PRIORITY_UPDATE frame for a stream (RFC 9218 section 7). */
void h2_priority_update(h2c *c, uint32_t id, const char *v, size_t n);
/* Gives the buffered request body to the handler as far as its credit goes. */
void h2_deliver(h2s *s);
/* The connection's own response on a stream it refuses (no handler): status page. */
void h2_reject(h2c *c, h2s *s, int status);

#endif

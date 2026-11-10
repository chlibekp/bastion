/* Private to the HTTP/1.1 connection: its two objects and the few functions conn.c and
 * stream_ops.c share. Nothing outside src/http/h1 includes this. */
#ifndef BST_HTTP_H1_CONN_PRIV_H
#define BST_HTTP_H1_CONN_PRIV_H

#include "http/h1/body.h"
#include "http/h1/conn.h"
#include "http/h1/parser.h"

#include <stdlib.h>

typedef struct h1c h1c;
typedef struct h1s h1s;

enum { M_HEAD, M_BODY, M_DISCARD };

struct h1s {
	bst_stream s; /* first: a bst_stream * is an h1s * */
	h1c *c;
	h1s *next;
	bst_h1_body body;
	bst_headers trailers;
	bst_chain in;  /* decoded request body not yet given to the handler */
	bst_chain pre; /* interim responses and the head, serialized */
	bst_chain out; /* body bytes, framed */
	uint64_t credit;
	size_t charged;
	bst_done_cb cb; /* the handler's outstanding send_body */
	void *cb_ud;
	int64_t cl_left; /* Content-Length bytes still to send, -1 when not counting */
	bool reading, body_done, end_sent;
	bool detached; /* the handler was told on_reset (or never had one) */
	bool own;      /* we are answering on our own behalf: ops are allowed though detached */
	bool head_sent, head_ready, pre_flush, resp_done, is_head, no_body, chunked;
	bool close_after, expect_sent;
};

struct h1c {
	h1c *prev, *next;
	bst_worker *w;
	bst_loop *loop;
	bst_transport *t;
	const bst_cfg_server_set *set;
	const bst_cfg_http *hc; /* connection-level figures: the listener's default server */
	h1s *head, *tail, *cur, *body_s;
	unsigned nq;
	unsigned long served;
	int mode;
	bst_buf *held; /* input not yet parsed because the pipeline is full */
	size_t held_off;
	char *hbuf; /* the head so far, when it spans reads */
	size_t hlen, hcap;
	bst_h1_parser parser;
	bst_chain wchain;
	bool writing;
	h1s *wr_s;
	bst_done_cb wr_cb;
	void *wr_ud;
	bst_timer t_head, t_body, t_send, t_flush;
	uint64_t win_bytes;
	bool recv_on, no_more, draining, closed, lingering, unread, flush_armed;
	int depth;
};


static inline void h1c_enter(h1c *c) { c->depth++; }
static inline void h1c_leave(h1c *c)
{
	if (--c->depth == 0 && c->closed)
		free(c);
}

void h1c_close(h1c *c);
void h1c_pump(h1c *c);
void h1c_update_recv(h1c *c);
void h1c_deliver(h1s *s);
void h1c_force_discard(h1c *c, h1s *s);
void h1c_arm_flush(h1c *c);
extern const bst_stream_ops bst_h1_ops;

#endif

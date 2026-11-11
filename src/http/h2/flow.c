/* HTTP/2 flow control (RFC 9113 section 5.2 and 6.9).
 *
 * Receiving. Each stream and the connection have a window the peer may send into. Credit goes
 * back (WINDOW_UPDATE) only for bytes a handler has taken, never for bytes that merely arrived, so
 * a handler that stops reading (or never asks for the body) stops the peer at the stream window
 * and cannot make Bastion buffer more than http2_initial_window per stream.
 *
 * Sending. The window the peer grants us gates the DATA frames sched.c builds; a stream waiting on
 * its window is not in the ready lists, and a window that never opens ends in a timeout
 * (sched.c, h2c_on_stall_timer). */
#include "http/h2/conn_priv.h"

#define H2_MAX_WINDOW 0x7fffffffLL

static void queue_update(h2c *c, uint32_t id, uint64_t inc)
{
	if (inc == 0 || c->closed)
		return;
	if (h2c_queue_ok(c, bst_h2_write_window_update(&c->ctl, id, (uint32_t)inc)))
		h2c_arm_flush(c);
}

uint32_t h2_recv_account(h2c *c, h2s *s, uint32_t length, bool *stream_err)
{
	*stream_err = false;
	c->recv_win -= length;
	if (c->recv_win < 0)
		return BST_H2_FLOW_CONTROL_ERROR; /* the peer sent past the connection window */
	if (s != NULL) {
		s->recv_win -= length;
		if (s->recv_win < 0) {
			*stream_err = true;
			return BST_H2_FLOW_CONTROL_ERROR;
		}
	}
	return 0;
}

/* Gives credit back once enough has accumulated: half a window (the fixed policy), or at every
 * opportunity (the eager one). Small frequent updates are what a window-drip attacker likes to
 * see from a server; half a window per update keeps the frame count low. */
static void credit(h2c *c, int64_t *win, uint64_t *pending, uint32_t target, uint32_t id)
{
	uint64_t threshold = c->cfg->recv_window_policy == BST_H2_WINDOW_EAGER ? 1 : target / 2;
	if (threshold == 0)
		threshold = 1;
	if (*pending < threshold)
		return;
	uint64_t room = *pending;
	if ((uint64_t)*win + room > (uint64_t)H2_MAX_WINDOW)
		room = (uint64_t)(H2_MAX_WINDOW - *win);
	*pending = 0;
	*win += (int64_t)room;
	queue_update(c, id, room);
}

void h2_recv_consumed(h2c *c, h2s *s, size_t n)
{
	if (n == 0 || c->closed)
		return;
	c->recv_pending += n;
	credit(c, &c->recv_win, &c->recv_pending, c->cfg->connection_window, 0);
	/* A stream that already received END_STREAM can take no more data: no credit for it. */
	if (s != NULL && !s->dead && !s->remote_closed) {
		s->recv_pending += n;
		credit(c, &s->recv_win, &s->recv_pending, c->cfg->initial_window, s->id);
	}
}

static void wake_stream(h2s *s, void *arg)
{
	(void)arg;
	h2_sched_update(s);
}

uint32_t h2_send_window_update(h2c *c, h2s *s, uint32_t inc, bool *stream_err)
{
	*stream_err = s != NULL;
	if (inc == 0)
		return BST_H2_PROTOCOL_ERROR; /* RFC 9113 section 6.9: a zero increment */
	int64_t *win = s != NULL ? &s->send_win : &c->send_win;
	if (*win + (int64_t)inc > H2_MAX_WINDOW)
		return BST_H2_FLOW_CONTROL_ERROR;
	*win += inc;
	if (s != NULL)
		h2_sched_update(s);
	else
		h2s_each(c, wake_stream, NULL);
	h2c_arm_flush(c);
	return 0;
}

static void shift_window(h2s *s, void *arg)
{
	int64_t delta = *(int64_t *)arg;
	s->send_win += delta; /* may go negative: the peer shrank the window below what is in flight */
}

uint32_t h2_set_initial_window(h2c *c, int64_t v)
{
	int64_t delta = v - c->peer_initial_window;
	if (delta == 0)
		return 0;
	if (delta > 0) { /* RFC 9113 section 6.9.2: a stream window past 2^31-1 is an error */
		for (unsigned b = 0; b < H2_BUCKETS; b++)
			for (h2s *s = c->bucket[b]; s != NULL; s = s->hnext)
				if (!s->dead && s->send_win + delta > H2_MAX_WINDOW)
					return BST_H2_FLOW_CONTROL_ERROR;
	}
	h2s_each(c, shift_window, &delta);
	c->peer_initial_window = v;
	if (delta > 0)
		h2s_each(c, wake_stream, NULL);
	h2c_arm_flush(c);
	return 0;
}

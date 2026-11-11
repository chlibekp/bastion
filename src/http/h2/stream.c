/* The stream table of an HTTP/2 connection, and how a stream ends. A stream is released in two
 * steps: h2s_kill takes it out of the table and the scheduler at once (so no later frame finds it),
 * and h2c_reap frees its memory later, never from inside a call a handler made on it. */
#include "http/h2/conn_priv.h"

#include "route/vhost.h"

#include <string.h>

#define ARENA_CHUNK H2_ARENA_CHUNK

static bst_slab *g_slab;

bst_slab *h2_slab(void)
{
	if (g_slab == NULL)
		g_slab = bst_chain_slab_new(64);
	return g_slab;
}

static unsigned bucket_of(uint32_t id)
{
	return (id >> 1) % H2_BUCKETS;
}

h2s *h2s_new(h2c *c, uint32_t id)
{
	bst_slab *slab = h2_slab();
	h2s *s = slab != NULL ? calloc(1, sizeof *s) : NULL;
	if (s == NULL)
		return NULL;
	s->s.arena = bst_arena_new(ARENA_CHUNK);
	if (s->s.arena == NULL) {
		free(s);
		return NULL;
	}
	s->c = c;
	s->id = id;
	s->cl_left = -1;
	s->send_win = c->peer_initial_window;
	s->recv_win = c->cfg->initial_window;
	s->urgency = H2_DEFAULT_URGENCY;
	bst_chain_init(&s->in, slab);
	bst_chain_init(&s->out, slab);
	bst_headers_init(&s->trailers, s->s.arena);
	bst_headers_init(&s->resp_trailers, s->s.arena);
	s->s.ops = &bst_h2_ops;
	s->s.proto = s;
	s->s.worker = c->w;
	s->s.transport = c->t;
	s->s.peer = c->peer;
	s->s.has_peer = c->has_peer;
	s->s.chain_slab = slab;
	s->s.server = bst_vhost_default(c->set);
	s->s.cfg = &s->s.server->common;
	bst_headers_init(&s->s.req.head.headers, s->s.arena);
	s->hnext = c->bucket[bucket_of(id)];
	c->bucket[bucket_of(id)] = s;
	c->nstreams++;
	if (id > c->last_stream)
		c->last_stream = id;
	return s;
}

h2s *h2s_find(h2c *c, uint32_t id)
{
	for (h2s *s = c->bucket[bucket_of(id)]; s != NULL; s = s->hnext)
		if (s->id == id && !s->dead)
			return s;
	return NULL;
}

static void unlink_s(h2s *s)
{
	h2s **pp = &s->c->bucket[bucket_of(s->id)];
	while (*pp != NULL && *pp != s)
		pp = &(*pp)->hnext;
	if (*pp == s)
		*pp = s->hnext;
	s->hnext = NULL;
}

void h2s_note_closed(h2c *c, uint32_t id, h2_closed_how how)
{
	c->ring[c->closed_next].id = id;
	c->ring[c->closed_next].how = (uint8_t)how;
	c->closed_next = (c->closed_next + 1) % H2_CLOSED_RING;
}

h2_closed_how h2s_closed_how(const h2c *c, uint32_t id)
{
	for (unsigned i = 0; i < H2_CLOSED_RING; i++)
		if (c->ring[i].id == id && c->ring[i].how != H2_CL_NONE)
			return (h2_closed_how)c->ring[i].how;
	return H2_CL_NONE;
}

void h2s_detach(h2s *s, bst_stream_err why)
{
	if (s->detached)
		return;
	s->detached = true;
	s->cb = NULL;
	if (s->s.handler != NULL && s->s.handler->on_reset != NULL)
		s->s.handler->on_reset(&s->s, why);
}

void h2s_kill(h2s *s, bst_stream_err why, h2_closed_how how)
{
	h2c *c = s->c;
	if (s->dead)
		return;
	if (why == BST_STREAM_ERR_NONE) { /* the handler finished: it gets no on_reset */
		s->detached = true;
		s->cb = NULL;
	} else {
		h2s_detach(s, why);
	}
	h2_sched_remove(s);
	if (s->in.len > 0) /* body the handler never took: the peer's window must not shrink for it */
		h2_recv_consumed(c, s, (size_t)s->in.len);
	bst_chain_clear(&s->in);
	bst_chain_clear(&s->out);
	s->dead = true;
	unlink_s(s);
	if (c->nstreams > 0)
		c->nstreams--;
	h2s_note_closed(c, s->id, how);
	if (!s->in_reap) {
		s->in_reap = true;
		s->dnext = c->reapq;
		c->reapq = s;
	}
	h2c_arm_idle(c);
	h2c_arm_flush(c); /* so the reaper runs even if nothing else wakes the connection */
}

/* The response is complete (and written): when the request is too, the stream is done; when the
 * request is still arriving, the peer is told to stop sending (RST_STREAM(NO_ERROR), RFC 9113
 * section 8.1). */
void h2s_check_done(h2s *s)
{
	if (s->dead || !s->local_closed || s->out.len > 0 || s->trailers_due)
		return;
	h2c *c = s->c;
	if (s->remote_closed) {
		h2s_kill(s, BST_STREAM_ERR_NONE, H2_CL_ENDED);
		return;
	}
	bst_h2_wr *w = &c->ctl;
	(void)h2c_queue_ok(c, bst_h2_write_rst(w, s->id, BST_H2_NO_ERROR));
	h2s_kill(s, BST_STREAM_ERR_NONE, H2_CL_LOCAL_RST);
}

static void free_stream(h2s *s)
{
	h2c *c = s->c;
	bst_chain_clear(&s->in);
	bst_chain_clear(&s->out);
	if (s->charged > 0 && c->w != NULL)
		bst_worker_mem_release(c->w, s->charged);
	bst_arena_free(s->s.arena);
	free(s);
}

void h2c_reap(h2c *c)
{
	h2s **pp = &c->reapq;
	while (*pp != NULL) {
		h2s *s = *pp;
		if (s->in_batch) { /* its data is in the write in flight: after that completes */
			pp = &s->dnext;
			continue;
		}
		*pp = s->dnext;
		free_stream(s);
	}
}

void h2s_each(h2c *c, void (*fn)(h2s *, void *), void *arg)
{
	for (unsigned b = 0; b < H2_BUCKETS; b++) {
		h2s *s = c->bucket[b], *nx;
		for (; s != NULL; s = nx) {
			nx = s->hnext;
			if (!s->dead)
				fn(s, arg);
		}
	}
}

/* The connection is gone: every stream is told, and everything is freed at once. */
void h2c_free_streams(h2c *c)
{
	for (unsigned b = 0; b < H2_BUCKETS; b++) {
		h2s *s = c->bucket[b];
		c->bucket[b] = NULL;
		while (s != NULL) {
			h2s *nx = s->hnext;
			s->hnext = NULL;
			if (!s->dead) {
				s->dead = true;
				h2s_detach(s, BST_STREAM_ERR_CANCEL);
				free_stream(s);
			}
			s = nx;
		}
	}
	for (h2s *s = c->reapq; s != NULL;) {
		h2s *nx = s->dnext;
		free_stream(s);
		s = nx;
	}
	c->reapq = NULL;
	c->nstreams = 0;
}

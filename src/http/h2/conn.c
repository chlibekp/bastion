/* HTTP/2 connection lifecycle: start, the read path, errors, timers, graceful shutdown.
 *
 * Re-entrancy. Handlers call back into streams from inside our callbacks, and a callback may close
 * the connection. Every entry point brackets itself with h2c_enter/h2c_leave: h2c_close releases
 * everything at once but the h2c itself is freed when the last bracket is left (as in h1/conn.c). */
#include "http/h2/conn_priv.h"

#include "core/log.h"

#include <string.h>

static h2c *g_conns;

static void on_recv(void *ud, bst_buf *data, int err);

bool h2c_charge(h2c *c, bst_h2_guard_kind kind)
{
	if (!bst_h2_guard_charge(&c->guard, &c->cfg->abuse, kind, bst_loop_now_ms(c->loop)))
		return false;
	bst_log(BST_LOG_INFO, "h2: closing a connection that used up its %s budget", bst_h2_guard_name(kind));
	bst_h2_guard_hit(kind);
	h2c_conn_error(c, BST_H2_ENHANCE_YOUR_CALM);
	return true;
}

/* ---- the end of the connection ---- */

void h2c_close(h2c *c)
{
	if (c->closed)
		return;
	c->closed = true;
	if (c->prev != NULL)
		c->prev->next = c->next;
	else
		g_conns = c->next;
	if (c->next != NULL)
		c->next->prev = c->prev;
	bst_timer_cancel(&c->t_idle);
	bst_timer_cancel(&c->t_settings);
	bst_timer_cancel(&c->t_send);
	bst_timer_cancel(&c->t_flush);
	bst_timer_cancel(&c->t_stall);
	bst_timer_cancel(&c->t_ling);
	c->t->ops->close(c->t);
	h2c_free_streams(c);
	c->batch = c->cbq = NULL;
	bst_chain_clear(&c->wchain);
	bst_h2_wr_free(&c->ctl);
	free(c->in);
	free(c->hb.buf);
	c->in = c->hb.buf = NULL;
	bst_hpack_dec_free(&c->dec);
	bst_hpack_enc_free(&c->enc);
	bst_arena_free(c->scratch);
	c->scratch = NULL;
	if (c->w != NULL)
		bst_worker_conn_closed(c->w);
	if (c->depth == 0)
		free(c);
}

bool h2c_queue_ok(h2c *c, int rc)
{
	if (rc != 0) {
		h2c_close(c);
		return false;
	}
	/* Control frames pile up when the peer does not read what it provokes (PING and SETTINGS
	 * acknowledgements, resets): past the limit it is not a client but a flood. */
	if (c->writing && c->ctl.len > c->cfg->abuse.control_queue_max) {
		bst_log(BST_LOG_INFO, "h2: control frames queued past http2_abuse control_queue_max");
		bst_h2_guard_hit(BST_H2G_CONTROL_QUEUE);
		h2c_close(c); /* no GOAWAY: it could not be delivered through the full queue either */
		return false;
	}
	return true;
}

void h2c_conn_error(h2c *c, uint32_t code)
{
	if (c->closed || c->dying)
		return;
	c->dying = true;
	if (!c->goaway_sent) {
		c->goaway_sent = true;
		if (bst_h2_write_goaway(&c->ctl, c->last_stream, code) != 0) {
			h2c_close(c);
			return;
		}
	}
	h2c_arm_flush(c); /* input is still read, and ignored, until the GOAWAY is out */
	h2c_pump(c);
}

void h2s_reset(h2s *s, uint32_t code, bst_stream_err why)
{
	h2c *c = s->c;
	if (s->dead)
		return;
	if (!c->dying && bst_h2_write_rst(&c->ctl, s->id, code) != 0) {
		h2c_close(c);
		return;
	}
	h2s_kill(s, why, H2_CL_LOCAL_RST);
	if (!c->closed)
		(void)h2c_queue_ok(c, 0);
	h2c_arm_flush(c);
}

void h2c_stream_error(h2c *c, uint32_t id, uint32_t code)
{
	/* A reset the client provoked costs it nothing to cause and us a frame to send: it is the
	 * MadeYouReset (CVE-2025-8671) surface, so it has a budget of its own. */
	if (h2c_charge(c, BST_H2G_SERVER_RST))
		return;
	h2s *s = h2s_find(c, id);
	if (s != NULL) {
		bst_stream_err why = code == BST_H2_PROTOCOL_ERROR ? BST_STREAM_ERR_PROTOCOL : BST_STREAM_ERR_CANCEL;
		h2s_reset(s, code, why);
		return;
	}
	if (c->dying)
		return;
	if (!h2c_queue_ok(c, bst_h2_write_rst(&c->ctl, id, code)))
		return;
	h2s_note_closed(c, id, H2_CL_LOCAL_RST);
	h2c_arm_flush(c);
}

/* ---- timers ---- */

static void on_idle(void *ud)
{
	h2c *c = ud;
	h2c_enter(c);
	h2c_conn_error(c, BST_H2_NO_ERROR);
	h2c_leave(c);
}

void h2c_arm_idle(h2c *c)
{
	if (c->closed)
		return;
	if (c->graceful_final && c->nstreams == 0 && !c->dying) {
		c->dying = true; /* the last stream of a draining connection is done: the GOAWAY already said so */
		h2c_arm_flush(c);
		return;
	}
	if (c->nstreams == 0 && !c->writing && !c->dying)
		bst_loop_timer_arm(c->loop, &c->t_idle, c->cfg->idle_timeout_ms, on_idle, c);
	else
		bst_timer_cancel(&c->t_idle);
}

static void on_partial(void *ud)
{
	h2c *c = ud;
	h2c_enter(c);
	bst_log(BST_LOG_DEBUG, "h2: input did not complete in time");
	if (!c->got_settings || !c->preface_ok)
		h2c_conn_error(c, BST_H2_SETTINGS_TIMEOUT);
	else
		h2c_conn_error(c, BST_H2_NO_ERROR);
	h2c_leave(c);
}

/* A deadline for what is half received: the client preface and SETTINGS, a frame split across
 * reads, a header block waiting for its END_HEADERS. It is armed when the state begins and not
 * moved by trickled bytes, so a client cannot hold a connection open one byte at a time. */
void h2c_update_partial(h2c *c)
{
	bool need = !c->got_settings || c->in_len > 0 || c->hb.active;
	if (!need || c->dying || c->closed) {
		bst_timer_cancel(&c->t_settings);
		c->partial_armed = false;
		return;
	}
	if (c->partial_armed)
		return;
	c->partial_armed = true;
	uint64_t ms = (!c->got_settings || c->hb.active) ? c->hc->client_header_timeout_ms
							 : c->hc->client_body_timeout_ms;
	bst_loop_timer_arm(c->loop, &c->t_settings, ms, on_partial, c);
}

/* ---- reading ---- */

/* Frames in buf[0..n); returns the bytes used. */
static size_t process(h2c *c, const uint8_t *buf, size_t n)
{
	size_t off = 0;
	while (off < n && !c->closed && !c->dying) {
		bst_h2_frame f;
		bst_h2_err err = { 0, 0 };
		ssize_t r = bst_h2_frame_parse(buf + off, n - off, c->cfg->max_frame_size, &f, &err);
		if (r == 0)
			break;
		if (r < 0) {
			if (err.stream == 0) {
				h2c_conn_error(c, err.code);
				return n;
			}
			/* A stream error in a frame that is entirely here: skip it (RFC 9113 section 4.2). */
			size_t len = (size_t)buf[off] << 16 | (size_t)buf[off + 1] << 8 | buf[off + 2];
			off += BST_H2_FRAME_HDR + len;
			h2c_stream_error(c, err.stream, err.code);
			continue;
		}
		off += (size_t)r;
		h2c_frame(c, &f);
	}
	return c->dying ? n : off;
}

static bool in_reserve(h2c *c, size_t need)
{
	if (need <= c->in_cap)
		return true;
	size_t cap = c->in_cap != 0 ? c->in_cap : 4096;
	while (cap < need)
		cap *= 2;
	uint8_t *p = realloc(c->in, cap);
	if (p == NULL)
		return false;
	c->in = p;
	c->in_cap = cap;
	return true;
}

/* Matches the client connection preface (RFC 9113 section 3.4); returns the bytes it used. */
static size_t preface(h2c *c, const uint8_t *p, size_t n)
{
	size_t take = BST_H2_PREFACE_LEN - c->preface_have;
	if (take > n)
		take = n;
	static const char pf[] = BST_H2_PREFACE;
	if (memcmp(p, pf + c->preface_have, take) != 0) {
		h2c_conn_error(c, BST_H2_PROTOCOL_ERROR);
		return n;
	}
	c->preface_have += take;
	if (c->preface_have == BST_H2_PREFACE_LEN)
		c->preface_ok = true;
	return take;
}

static void feed(h2c *c, const uint8_t *p, size_t n)
{
	if (!c->preface_ok) {
		size_t used = preface(c, p, n);
		p += used;
		n -= used;
		if (n == 0 || c->dying || c->closed)
			return;
	}
	const uint8_t *src = p;
	size_t len = n;
	if (c->in_len > 0) {
		if (!in_reserve(c, c->in_len + n)) {
			h2c_close(c);
			return;
		}
		memcpy(c->in + c->in_len, p, n);
		c->in_len += n;
		src = c->in;
		len = c->in_len;
	}
	size_t used = process(c, src, len);
	if (c->closed)
		return;
	if (used < len) {
		size_t rest = len - used;
		if (src == c->in) {
			memmove(c->in, c->in + used, rest);
		} else {
			if (!in_reserve(c, rest)) {
				h2c_close(c);
				return;
			}
			memcpy(c->in, src + used, rest);
		}
		c->in_len = rest;
	} else {
		c->in_len = 0;
	}
	if (c->in_len > 0 && c->in_cap > 65536 + 4096 && c->in_len < 4096) { /* a big buffer is not kept for a small tail */
		uint8_t *q = realloc(c->in, 4096);
		if (q != NULL) {
			c->in = q;
			c->in_cap = 4096;
		}
	}
}

void h2c_update_recv(h2c *c)
{
	if (c->closed || c->recv_on)
		return;
	if (c->t->ops->recv_start(c->t, on_recv, c) == 0)
		c->recv_on = true;
	else
		h2c_close(c);
}

static void on_recv(void *ud, bst_buf *data, int err)
{
	h2c *c = ud;
	h2c_enter(c);
	if (data == NULL || err != 0) {
		c->recv_on = false;
		h2c_close(c);
		h2c_leave(c);
		return;
	}
	if (!c->lingering && !c->dying)
		feed(c, data->data, data->len);
	bst_buf_unref(data);
	if (!c->closed) {
		h2c_update_partial(c);
		h2c_arm_idle(c);
		h2c_pump(c);
		if (c->depth == 1)
			h2c_reap(c);
	}
	h2c_leave(c);
}

/* ---- start ---- */

static bool queue_settings(h2c *c)
{
	const bst_cfg_h2 *h = c->cfg;
	uint32_t e[8][2];
	size_t n = 0;
	e[n][0] = BST_H2_S_HEADER_TABLE_SIZE, e[n++][1] = h->header_table_size;
	e[n][0] = BST_H2_S_ENABLE_PUSH, e[n++][1] = 0;
	e[n][0] = BST_H2_S_MAX_CONCURRENT_STREAMS, e[n++][1] = h->max_concurrent_streams;
	e[n][0] = BST_H2_S_INITIAL_WINDOW_SIZE, e[n++][1] = h->initial_window;
	e[n][0] = BST_H2_S_MAX_FRAME_SIZE, e[n++][1] = h->max_frame_size;
	e[n][0] = BST_H2_S_MAX_HEADER_LIST_SIZE, e[n++][1] = h->max_header_list_size;
	if (h->connect_protocol)
		e[n][0] = BST_H2_S_ENABLE_CONNECT_PROTOCOL, e[n++][1] = 1;
	/* RFC 9218 section 2.1: the RFC 7540 priority tree is not used here, and saying so lets
	 * clients skip sending it. */
	e[n][0] = BST_H2_S_NO_RFC7540_PRIORITIES, e[n++][1] = 1;
	if (bst_h2_write_settings(&c->ctl, (const uint32_t(*)[2])e, n, false) != 0)
		return false;
	if (h->connection_window > 65535u) { /* the connection window starts at 65535 whatever the setting */
		uint32_t inc = h->connection_window - 65535u;
		if (bst_h2_write_window_update(&c->ctl, 0, inc) != 0)
			return false;
		c->recv_win += inc;
	}
	return true;
}

int bst_conn_h2_start_loop(bst_loop *loop, bst_worker *w, bst_transport *t, const bst_listener_set *set,
			   const bst_sockaddr *peer, const void *prefix, size_t prefix_len, bool syn_data)
{
	h2c *c = calloc(1, sizeof *c);
	const bst_cfg_server *def = bst_vhost_default(set);
	if (c == NULL || def == NULL || h2_slab() == NULL) {
		free(c);
		t->ops->close(t);
		return -1;
	}
	c->w = w;
	c->loop = loop;
	c->t = t;
	c->set = set;
	c->syn_data = syn_data;
	if (peer != NULL) {
		c->peer = *peer;
		c->has_peer = true;
	}
	c->hc = &def->common.http;
	c->cfg = &c->hc->h2;
	c->peer_max_frame = 16384;
	c->peer_initial_window = 65535;
	c->send_win = c->recv_win = 65535;
	uint32_t enc_cap = c->cfg->header_table_size < 4096 ? c->cfg->header_table_size : 4096;
	bst_hpack_dec_init(&c->dec, c->cfg->header_table_size);
	bst_hpack_enc_init(&c->enc, enc_cap);
	c->scratch = bst_arena_new(4096);
	bst_chain_init(&c->wchain, h2_slab());
	bst_timer_init(&c->t_idle);
	bst_timer_init(&c->t_settings);
	bst_timer_init(&c->t_send);
	bst_timer_init(&c->t_flush);
	bst_timer_init(&c->t_stall);
	bst_timer_init(&c->t_ling);
	c->next = g_conns;
	if (g_conns != NULL)
		g_conns->prev = c;
	g_conns = c;
	if (w != NULL)
		bst_worker_conn_opened(w);
	h2c_enter(c);
	if (c->scratch == NULL || !queue_settings(c)) {
		h2c_close(c);
		h2c_leave(c);
		return -1;
	}
	if (prefix_len > 0)
		feed(c, prefix, prefix_len);
	h2c_update_partial(c);
	if (!c->closed) {
		h2c_update_recv(c);
		h2c_arm_idle(c);
		h2c_pump(c);
	}
	h2c_leave(c);
	return 0;
}

int bst_conn_h2_start(bst_worker *w, bst_transport *t, const bst_listener_set *set,
		      const bst_sockaddr *peer, const void *prefix, size_t prefix_len, bool syn_data)
{
	return bst_conn_h2_start_loop(bst_worker_loop(w), w, t, set, peer, prefix, prefix_len, syn_data);
}

/* ---- graceful shutdown (RFC 9113 section 6.8) ---- */

/* Phase one: a GOAWAY that names no limit and a PING. The client's answer to the PING proves the
 * GOAWAY has arrived, so every stream it started before that is one the server will answer; the
 * final GOAWAY (frames.c, on the PING acknowledgement) then names the last of them. */
void h2c_graceful(h2c *c)
{
	if (c->closed || c->dying || c->graceful)
		return;
	c->graceful = true;
	if (c->nstreams == 0) {
		c->graceful_final = true;
		c->goaway_sent = true;
		(void)bst_h2_write_goaway(&c->ctl, c->last_stream, BST_H2_NO_ERROR);
		c->dying = true;
		h2c_arm_flush(c);
		return;
	}
	uint8_t tok[8] = { 'b', 's', 't', 'd', 'r', 'a', 'i', 'n' };
	if (bst_h2_write_goaway(&c->ctl, 0x7fffffffu, BST_H2_NO_ERROR) != 0 ||
	    bst_h2_write_ping(&c->ctl, tok, false) != 0) {
		h2c_close(c);
		return;
	}
	h2c_arm_flush(c);
}

void bst_h2_drain(bst_worker *w)
{
	(void)w;
	h2c *nx;
	for (h2c *c = g_conns; c != NULL; c = nx) {
		nx = c->next;
		h2c_enter(c);
		h2c_graceful(c);
		h2c_leave(c);
	}
}

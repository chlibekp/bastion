/* See h3_bridge.h. Where an HTTP/3 request stream meets the HTTP semantics layer, the way
 * http/h2/bridge.c does it for HTTP/2: what decides whether a request is acceptable is shared
 * (validate_pseudo.c, semantics.c, the router), and this file adds the connection policies (virtual
 * host, 0-RTT, memory budget) and the mapping of responses onto nghttp3. */
#include "http/h3/h3_bridge.h"

#include "core/chain.h"
#include "core/log.h"
#include "core/wheel.h"
#include "http/stream.h"
#include "http/token.h"
#include "http/validate_pseudo.h"
#include "proc/worker.h"
#include "tls/conn.h"

#include <errno.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#ifndef BST_VERSION
#define BST_VERSION "0.0.0"
#endif

#define ARENA_CHUNK 4096u	   /* a stream's arena grows by this much; its share of the budget */
#define READ_CHUNK (64u * 1024u)   /* one file read */
#define KICK_MS 1u		   /* the loop has no "run soon": the shortest timer */
#define MAX_VEC 16

typedef struct h3s h3s;

struct h3s {
	bst_stream s; /* first: a bst_stream * is an h3s * */
	bst_h3_conn *c;
	int64_t id;
	h3s *prev, *next;	/* every stream of the connection */
	h3s *dnext;		/* the list of streams with a send_body callback due */
	bool in_due;
	/* request */
	bst_headers fields;	/* the header section being received */
	bst_headers trailers;
	uint64_t field_bytes;
	bool in_trailers, too_large, field_oom;
	bool remote_closed, end_sent, reading, rejected, expect_sent;
	uint64_t credit;	/* body bytes the handler asked for */
	bst_chain in;		/* body received, not yet given to the handler */
	uint64_t body_seen;
	/* response */
	bst_chain out;		/* what the handler gave, not yet staged */
	bst_chain ready;	/* staged in memory, not yet handed to nghttp3 */
	bst_chain flight;	/* handed to nghttp3, not yet acknowledged by the client */
	bst_done_cb cb;		/* the handler's outstanding send_body */
	void *cb_ud;
	size_t cb_bytes;
	bool head_sent, resp_done, eof_given, is_head, no_body, trailers_due, blocked;
	int64_t cl_left;	/* Content-Length bytes still to send, -1 when not counting */
	bst_headers resp_trailers;
	/* lifecycle */
	bool dead;		/* ended: freed when nghttp3 closes the stream */
	bool detached;		/* the handler was told on_reset, or finished */
	bool own;		/* the connection answers on its own behalf: ops work though detached */
	uint64_t abort_code;	/* reset both directions with this code at the next kick, 0: none */
	bool stop_due;		/* the response is complete: STOP_SENDING(H3_NO_ERROR) at the next kick */
	size_t charged;
};

struct bst_h3_conn {
	bst_h3_env env;
	nghttp3_conn *h3;
	h3s *streams;
	unsigned nstreams;
	h3s *due;
	bst_timer t_kick;
	bool draining, close_due, aborts_due;
};

extern const bst_stream_ops bst_h3_ops;
static void resp_complete(h3s *s);

#define S(bs) ((h3s *)(bs))
#define LIVE(s) (!(s)->dead && (!(s)->detached || (s)->own))

static bst_slab *g_slab;

static bst_slab *slab(void)
{
	if (g_slab == NULL)
		g_slab = bst_chain_slab_new(64);
	return g_slab;
}

static uint64_t now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

/* ---- the kick: deferred work, then the connection writes ---- */

static void on_kick(void *ud);

static void kick(bst_h3_conn *c)
{
	bst_loop_timer_arm(c->env.loop, &c->t_kick, KICK_MS, on_kick, c);
}

/* QUIC credit for n bytes of the stream the bridge is done with. */
static void credit(bst_h3_conn *c, int64_t sid, uint64_t n)
{
	if (n == 0)
		return;
	(void)ngtcp2_conn_extend_max_stream_offset(c->env.q, sid, n);
	ngtcp2_conn_extend_max_offset(c->env.q, n);
}

/* ---- stream lifetime ---- */

static h3s *find(bst_h3_conn *c, int64_t sid)
{
	for (h3s *s = c->streams; s != NULL; s = s->next)
		if (s->id == sid)
			return s;
	return NULL;
}

static void due_remove(h3s *s)
{
	if (!s->in_due)
		return;
	for (h3s **p = &s->c->due; *p != NULL; p = &(*p)->dnext)
		if (*p == s) {
			*p = s->dnext;
			break;
		}
	s->in_due = false;
}

static void detach(h3s *s, bst_stream_err why)
{
	if (s->detached)
		return;
	s->detached = true;
	s->cb = NULL;
	if (s->s.handler != NULL && s->s.handler->on_reset != NULL)
		s->s.handler->on_reset(&s->s, why);
}

/* Ends the stream for the handler: told on_reset (why) unless it finished (NONE). Its memory
 * stays until nghttp3 closes the stream: what is in flight may still be retransmitted. */
static void kill(h3s *s, bst_stream_err why)
{
	if (s->dead)
		return;
	if (why == BST_STREAM_ERR_NONE) {
		s->detached = true;
		s->cb = NULL;
	} else {
		detach(s, why);
	}
	s->dead = true;
	due_remove(s);
	credit(s->c, s->id, s->in.len); /* body the handler never took */
	bst_chain_clear(&s->in);
	bst_chain_clear(&s->out);
	bst_chain_clear(&s->ready);
}

/* Resets both directions (deferred to the kick: never from inside nghttp3's own callbacks). */
static void abort_stream(h3s *s, uint64_t code, bst_stream_err why)
{
	if (s->abort_code == 0)
		s->abort_code = code;
	s->c->aborts_due = true;
	kill(s, why);
	kick(s->c);
}

static void free_stream(h3s *s)
{
	bst_h3_conn *c = s->c;
	due_remove(s);
	if (s->prev != NULL)
		s->prev->next = s->next;
	else
		c->streams = s->next;
	if (s->next != NULL)
		s->next->prev = s->prev;
	c->nstreams--;
	bst_chain_clear(&s->in);
	bst_chain_clear(&s->out);
	bst_chain_clear(&s->ready);
	bst_chain_clear(&s->flight);
	if (s->charged > 0 && c->env.w != NULL)
		bst_worker_mem_release(c->env.w, s->charged);
	bst_arena_free(s->s.arena);
	free(s);
}

static h3s *stream_new(bst_h3_conn *c, int64_t sid)
{
	bst_slab *sl = slab();
	h3s *s = sl != NULL ? calloc(1, sizeof *s) : NULL;
	if (s == NULL)
		return NULL;
	s->s.arena = bst_arena_new(ARENA_CHUNK);
	if (s->s.arena == NULL) {
		free(s);
		return NULL;
	}
	s->c = c;
	s->id = sid;
	s->cl_left = -1;
	bst_chain_init(&s->in, sl);
	bst_chain_init(&s->out, sl);
	bst_chain_init(&s->ready, sl);
	bst_chain_init(&s->flight, sl);
	bst_headers_init(&s->fields, s->s.arena);
	bst_headers_init(&s->trailers, s->s.arena);
	bst_headers_init(&s->resp_trailers, s->s.arena);
	s->s.ops = &bst_h3_ops;
	s->s.proto = s;
	s->s.worker = c->env.w;
	s->s.transport = c->env.t;
	s->s.peer = c->env.peer;
	s->s.has_peer = true;
	s->s.chain_slab = sl;
	s->s.server = bst_vhost_default(c->env.set);
	s->s.cfg = &s->s.server->common;
	bst_headers_init(&s->s.req.head.headers, s->s.arena);
	s->next = c->streams;
	if (c->streams != NULL)
		c->streams->prev = s;
	c->streams = s;
	c->nstreams++;
	return s;
}

/* ---- the response body: staging and the send_body callback ---- */

/* Moves what the handler gave into memory, up to BST_H3_STREAM_BUF ahead of what the client
 * acknowledged: memory segments as they are, file segments read in READ_CHUNK pieces. 0, or -1 on
 * a read error or exhaustion. */
static int stage(h3s *s)
{
	while (s->out.len > 0 && s->ready.len + s->flight.len < BST_H3_STREAM_BUF) {
		int fd;
		off_t off, len;
		if (bst_chain_front_file(&s->out, &fd, &off, &len)) {
			size_t want = (uint64_t)len < READ_CHUNK ? (size_t)len : READ_CHUNK;
			bst_buf *b = bst_buf_new(want);
			if (b == NULL)
				return -1;
			ssize_t r = pread(fd, b->data, want, off);
			if (r <= 0) {
				bst_log(BST_LOG_ERROR, "h3: reading a response file: %s",
					r < 0 ? strerror(errno) : "it is shorter than its segment");
				bst_buf_unref(b);
				return -1;
			}
			b->len = (size_t)r;
			int rc = bst_chain_add_mem(&s->ready, b, 0, (size_t)r);
			bst_buf_unref(b);
			if (rc != 0)
				return -1;
			bst_chain_consume(&s->out, (uint64_t)r);
		} else {
			struct iovec iov[MAX_VEC];
			int n = bst_chain_to_iov(&s->out, iov, MAX_VEC);
			uint64_t total = 0;
			for (int i = 0; i < n; i++)
				total += iov[i].iov_len;
			if (total == 0 || bst_chain_take(&s->ready, &s->out, total) != 0)
				return -1;
		}
	}
	return 0;
}

/* The handler's send_body callback is due once everything it gave is staged. */
static void check_cb(h3s *s)
{
	if (s->cb == NULL || s->in_due || s->out.len > 0 || s->dead)
		return;
	s->in_due = true;
	s->dnext = s->c->due;
	s->c->due = s;
	kick(s->c);
}

static void unblock(h3s *s)
{
	if (s->blocked && (s->out.len > 0 || s->ready.len > 0 || s->resp_done)) {
		s->blocked = false;
		(void)nghttp3_conn_resume_stream(s->c->h3, s->id);
	}
}

static nghttp3_ssize read_data(nghttp3_conn *conn, int64_t sid, nghttp3_vec *vec, size_t veccnt,
			       uint32_t *pflags, void *cud, void *sud)
{
	(void)conn, (void)cud, (void)sid;
	h3s *s = sud;
	if (s == NULL || s->dead) {
		*pflags |= NGHTTP3_DATA_FLAG_EOF;
		return 0;
	}
	if (stage(s) != 0) {
		abort_stream(s, BST_H3_INTERNAL_ERROR, BST_STREAM_ERR_INTERNAL);
		s->blocked = true;
		return NGHTTP3_ERR_WOULDBLOCK;
	}
	struct iovec iov[MAX_VEC];
	int n = bst_chain_to_iov(&s->ready, iov, veccnt < MAX_VEC ? (int)veccnt : MAX_VEC);
	uint64_t total = 0;
	for (int i = 0; i < n; i++) {
		vec[i].base = iov[i].iov_base;
		vec[i].len = iov[i].iov_len;
		total += iov[i].iov_len;
	}
	if (total > 0 && bst_chain_take(&s->flight, &s->ready, total) != 0)
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	if (s->resp_done && s->out.len == 0 && s->ready.len == 0) {
		*pflags |= NGHTTP3_DATA_FLAG_EOF;
		s->eof_given = true;
		resp_complete(s);
		if (s->trailers_due) {
			uint32_t nt = s->resp_trailers.n;
			nghttp3_nv *nv = bst_arena_alloc(s->s.arena, (nt ? nt : 1) * sizeof *nv);
			if (nv != NULL) {
				for (uint32_t i = 0; i < nt; i++)
					nv[i] = (nghttp3_nv){ (uint8_t *)(uintptr_t)s->resp_trailers.v[i].name.p,
							      (uint8_t *)(uintptr_t)s->resp_trailers.v[i].value.p,
							      s->resp_trailers.v[i].name.len,
							      s->resp_trailers.v[i].value.len, NGHTTP3_NV_FLAG_NONE };
				if (nghttp3_conn_submit_trailers(s->c->h3, s->id, nv, nt) == 0)
					*pflags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
			}
		}
	} else if (total == 0) {
		s->blocked = true;
		return NGHTTP3_ERR_WOULDBLOCK;
	}
	check_cb(s);
	return n;
}

/* ---- the stream ops ---- */

static bool conn_specific(bst_hdr_id id)
{
	return id == BST_H_CONNECTION || id == BST_H_KEEP_ALIVE || id == BST_H_PROXY_CONNECTION ||
	       id == BST_H_TRANSFER_ENCODING || id == BST_H_UPGRADE;
}

/* A lower-case copy of a field name (HTTP/3 field names are lower case, RFC 9114 section 4.2). */
static bool add_lower(bst_arena *a, nghttp3_nv *nv, bst_str name, bst_str value)
{
	char *p = bst_arena_alloc(a, name.len + 1u);
	if (p == NULL)
		return false;
	for (uint32_t i = 0; i < name.len; i++) {
		char ch = name.p[i];
		p[i] = ch >= 'A' && ch <= 'Z' ? (char)(ch + 32) : ch;
	}
	*nv = (nghttp3_nv){ (uint8_t *)p, (uint8_t *)(uintptr_t)value.p, name.len, value.len, NGHTTP3_NV_FLAG_NONE };
	return true;
}

static int h3_send_head(bst_stream *bs, const bst_resp_head *hin, bool end)
{
	h3s *s = S(bs);
	if (!LIVE(s) || s->head_sent || s->resp_done || hin->status < 200 || hin->status > 599)
		return -1;
	int st = hin->status;
	s->no_body = s->is_head || st == 204 || st == 304;
	uint32_t cap = hin->headers.n + 4;
	nghttp3_nv *nv = bst_arena_alloc(s->s.arena, cap * sizeof *nv);
	char *sv = bst_arena_alloc(s->s.arena, 8);
	if (nv == NULL || sv == NULL)
		goto fail;
	snprintf(sv, 8, "%d", st);
	uint32_t n = 0;
	nv[n++] = (nghttp3_nv){ (uint8_t *)":status", (uint8_t *)sv, 7, 3, NGHTTP3_NV_FLAG_NONE };
	bool has_date = false, has_server = false;
	for (uint32_t i = 0; i < hin->headers.n; i++) {
		const bst_header *h = &hin->headers.v[i];
		if (conn_specific(h->id) || h->id == BST_H_CONTENT_LENGTH || (h->name.len > 0 && h->name.p[0] == ':'))
			continue;
		has_date |= h->id == BST_H_DATE;
		has_server |= h->id == BST_H_SERVER;
		if (!add_lower(s->s.arena, &nv[n++], h->name, h->value))
			goto fail;
	}
	if (!has_date) {
		bst_str d = bst_http_date();
		char *dp = bst_arena_alloc(s->s.arena, d.len);
		if (dp == NULL)
			goto fail;
		memcpy(dp, d.p, d.len);
		nv[n++] = (nghttp3_nv){ (uint8_t *)"date", (uint8_t *)dp, 4, d.len, NGHTTP3_NV_FLAG_NONE };
	}
	if (!has_server) {
		bst_str sv2 = s->s.cfg->http.server_tokens ? BST_S("bastion/" BST_VERSION) : BST_S("bastion");
		nv[n++] = (nghttp3_nv){ (uint8_t *)"server", (uint8_t *)(uintptr_t)sv2.p, 6, sv2.len, NGHTTP3_NV_FLAG_NONE };
	}
	if (st != 204 && st != 304) {
		int64_t cl = hin->content_length;
		if (cl < 0 && end && !s->is_head)
			cl = 0;
		if (cl >= 0) {
			char *lv = bst_arena_alloc(s->s.arena, 24);
			int ln = lv != NULL ? snprintf(lv, 24, "%lld", (long long)cl) : 0;
			if (ln <= 0)
				goto fail;
			nv[n++] = (nghttp3_nv){ (uint8_t *)"content-length", (uint8_t *)lv, 14, (size_t)ln,
						NGHTTP3_NV_FLAG_NONE };
			if (!s->no_body)
				s->cl_left = cl;
		}
	}
	static const nghttp3_data_reader dr = { .read_data = read_data };
	if (nghttp3_conn_submit_response(s->c->h3, s->id, nv, n, end ? NULL : &dr) != 0)
		goto fail;
	s->head_sent = true;
	if (end) {
		s->resp_done = s->eof_given = true;
		resp_complete(s);
	}
	kick(s->c);
	return 0;
fail:
	abort_stream(s, BST_H3_INTERNAL_ERROR, BST_STREAM_ERR_INTERNAL);
	return -1;
}

static int h3_send_interim(bst_stream *bs, int status, const bst_headers *extra)
{
	h3s *s = S(bs);
	if (!LIVE(s) || s->head_sent || status < 100 || status > 199 || status == 101)
		return -1;
	uint32_t cap = (extra != NULL ? extra->n : 0) + 1;
	nghttp3_nv *nv = bst_arena_alloc(s->s.arena, cap * sizeof *nv);
	char *sv = bst_arena_alloc(s->s.arena, 8);
	if (nv == NULL || sv == NULL)
		return -1;
	snprintf(sv, 8, "%d", status);
	uint32_t n = 0;
	nv[n++] = (nghttp3_nv){ (uint8_t *)":status", (uint8_t *)sv, 7, 3, NGHTTP3_NV_FLAG_NONE };
	for (uint32_t i = 0; extra != NULL && i < extra->n; i++)
		if (!conn_specific(extra->v[i].id) && extra->v[i].id != BST_H_CONTENT_LENGTH &&
		    !add_lower(s->s.arena, &nv[n++], extra->v[i].name, extra->v[i].value))
			return -1;
	if (nghttp3_conn_submit_info(s->c->h3, s->id, nv, n) != 0)
		return -1;
	kick(s->c);
	return 0;
}

static int h3_send_body(bst_stream *bs, bst_chain *data, bool end, bst_done_cb cb, void *ud)
{
	h3s *s = S(bs);
	if (!LIVE(s) || !s->head_sent || s->resp_done || s->cb != NULL)
		return -1;
	uint64_t len = bst_chain_len(data);
	bool ok = true;
	if (s->no_body) {
		bst_chain_clear(data);
	} else if (s->cl_left >= 0 && len > (uint64_t)s->cl_left) {
		ok = false; /* more than the Content-Length said */
	} else {
		if (s->cl_left >= 0)
			s->cl_left -= (int64_t)len;
		if (end && s->cl_left > 0)
			ok = false; /* fewer: the client would wait for bytes that never come */
		else
			ok = bst_chain_move(&s->out, data) == 0;
	}
	if (!ok) {
		abort_stream(s, BST_H3_INTERNAL_ERROR, BST_STREAM_ERR_INTERNAL);
		return -1;
	}
	if (end)
		s->resp_done = true;
	s->cb = cb;
	s->cb_ud = ud;
	s->cb_bytes = (size_t)len;
	if (stage(s) != 0) {
		abort_stream(s, BST_H3_INTERNAL_ERROR, BST_STREAM_ERR_INTERNAL);
		return -1;
	}
	unblock(s);
	check_cb(s);
	kick(s->c);
	return 0;
}

static int h3_send_trailers(bst_stream *bs, const bst_headers *t)
{
	h3s *s = S(bs);
	if (!LIVE(s) || !s->head_sent || s->resp_done || s->trailers_due || s->no_body || t->n == 0)
		return -1;
	for (uint32_t i = 0; i < t->n; i++) {
		const bst_header *h = &t->v[i];
		if (!bst_is_token(h->name) || h->name.p[0] == ':' || conn_specific(h->id) ||
		    h->id == BST_H_CONTENT_LENGTH || !bst_is_field_value_clean(h->value))
			return -1;
		nghttp3_nv tmp;
		if (!add_lower(s->s.arena, &tmp, h->name, h->value) ||
		    bst_headers_add(&s->resp_trailers, (bst_str){ (const char *)tmp.name, (uint32_t)tmp.namelen },
				    h->value) != 0)
			return -1;
	}
	s->trailers_due = true;
	s->resp_done = true;
	s->blocked = true;
	unblock(s);
	kick(s->c);
	return 0;
}

/* Gives the buffered request body to the handler as far as its credit goes; QUIC credit goes
 * back to the client for what it took. */
static void deliver(h3s *s)
{
	bst_h3_conn *c = s->c;
	while (!s->dead && s->reading && !s->detached && s->s.handler != NULL) {
		bool data = s->in.len > 0;
		bool end_due = s->remote_closed && !s->end_sent;
		if (!data && !end_due)
			break;
		if (data && s->credit == 0)
			break;
		uint64_t n = s->in.len;
		if (data)
			s->credit = s->credit > n ? s->credit - n : 0;
		bool end = s->remote_closed;
		if (end)
			s->end_sent = true;
		credit(c, s->id, n);
		if (n > 0)
			kick(c); /* MAX_STREAM_DATA and MAX_DATA go out */
		if (end && s->trailers.n > 0 && s->s.handler->on_trailers != NULL)
			s->s.handler->on_trailers(&s->s, &s->trailers);
		if (s->dead || s->detached)
			break;
		if (s->s.handler->on_body != NULL)
			s->s.handler->on_body(&s->s, &s->in, end);
		if (s->dead)
			break;
		bst_chain_clear(&s->in);
		if (end)
			break;
	}
}

static void h3_read_body(bst_stream *bs, size_t cr)
{
	h3s *s = S(bs);
	if (!LIVE(s))
		return;
	s->reading = true;
	s->credit = cr > UINT64_MAX - s->credit ? UINT64_MAX : s->credit + cr;
	if (s->s.req.expect_continue && !s->expect_sent && !s->head_sent && !s->remote_closed) {
		s->expect_sent = true;
		(void)h3_send_interim(bs, 100, NULL);
	}
	deliver(s);
}

static void h3_reset_op(bst_stream *bs, bst_stream_err why)
{
	h3s *s = S(bs);
	if (!LIVE(s))
		return;
	uint64_t code = why == BST_STREAM_ERR_PROTOCOL ? BST_H3_MESSAGE_ERROR
			: why == BST_STREAM_ERR_INTERNAL ? BST_H3_INTERNAL_ERROR
							   : BST_H3_REQUEST_CANCELLED;
	abort_stream(s, code, why == BST_STREAM_ERR_NONE ? BST_STREAM_ERR_CANCEL : why);
}

const bst_stream_ops bst_h3_ops = {
	.send_head = h3_send_head,
	.send_interim = h3_send_interim,
	.send_body = h3_send_body,
	.send_trailers = h3_send_trailers,
	.read_body = h3_read_body,
	.reset = h3_reset_op,
};

/* The response is complete (all of it with nghttp3): the handler is done with the stream. A
 * request still arriving is not needed any more (RFC 9114 section 4.1: STOP_SENDING with
 * H3_NO_ERROR). */
static void resp_complete(h3s *s)
{
	if (!s->remote_closed && !s->dead) {
		s->stop_due = true; /* at the kick: never from inside nghttp3's own callbacks */
		s->c->aborts_due = true;
		kick(s->c);
	}
}

/* ---- requests ---- */

static void reject(h3s *s, int status)
{
	s->rejected = true;
	s->own = true;
	(void)bst_send_error(&s->s, status);
	s->own = false;
}

static void reject_retry_after(h3s *s, int status)
{
	const bst_cfg_limits *lim = bst_worker_limits(s->c->env.w);
	char *v = bst_arena_alloc(s->s.arena, 16);
	int n = v != NULL ? snprintf(v, 16, "%u", lim->overload_retry_after) : 0;
	s->rejected = true;
	s->own = true;
	(void)bst_send_error_hdr(&s->s, status, BST_S("Retry-After"), (bst_str){ v, n > 0 ? (uint32_t)n : 0 });
	s->own = false;
}

static void request_start(h3s *s, bool fin)
{
	bst_h3_conn *c = s->c;
	bst_req *rq = &s->s.req;
	s->remote_closed = fin;
	if (s->field_oom) {
		abort_stream(s, BST_H3_INTERNAL_ERROR, BST_STREAM_ERR_INTERNAL);
		return;
	}
	if (s->too_large) {
		reject(s, 431);
		return;
	}
	bst_pseudo_opts po = { .end_stream = fin, .allow_protocol = false };
	bst_pseudo_result pr;
	bst_pseudo_rc prc = bst_validate_pseudo_request(&s->fields, s->s.arena, &rq->head, &po, &pr);
	if (prc == BST_PSEUDO_MALFORMED) {
		/* RFC 9114 section 4.1.2: a malformed request is a stream error H3_MESSAGE_ERROR. */
		abort_stream(s, BST_H3_MESSAGE_ERROR, BST_STREAM_ERR_PROTOCOL);
		return;
	}
	if (prc == BST_PSEUDO_BAD_REQUEST) {
		reject(s, 400);
		return;
	}
	if (pr.has_length && pr.length > 0)
		rq->framing = (bst_framing){ BST_FRAMING_LENGTH, pr.length };
	else if (!fin && !pr.has_length)
		rq->framing = (bst_framing){ BST_FRAMING_CHUNKED, 0 }; /* a body of unknown length */
	else
		rq->framing = (bst_framing){ BST_FRAMING_NONE, 0 };
	int st = bst_validate_request_semantics(rq);
	if (st != 0) {
		reject(s, st);
		return;
	}
	if (rq->head.method == BST_M_HEAD)
		s->is_head = true;
	bool matched = true;
	s->s.server = bst_vhost_lookup(c->env.set, rq->host, &matched);
	s->s.cfg = &s->s.server->common;
	const bst_cfg_server *def = bst_vhost_default(c->env.set);
	if (!matched && def->unknown_host == BST_UNKNOWN_HOST_CLOSE) {
		c->close_due = true;
		abort_stream(s, BST_H3_REQUEST_REJECTED, BST_STREAM_ERR_CANCEL);
		return;
	}
	if (!matched && def->unknown_host == BST_UNKNOWN_HOST_421) {
		reject(s, 421);
		return;
	}
	const bst_cfg_server *sni = bst_tls_sni_server(c->env.t), *chosen = bst_tls_chosen_server(c->env.t);
	bool mtls_cross = chosen != NULL && chosen != s->s.server &&
			  (s->s.server->tls.client_auth != BST_CLIENT_AUTH_OFF ||
			   chosen->tls.client_auth != BST_CLIENT_AUTH_OFF);
	if (mtls_cross || (sni != NULL && sni != s->s.server && sni->tls.host_sni == BST_HOST_SNI_421)) {
		reject(s, 421); /* connection coalescing across hosts (RFC 9110 section 7.4) is refused */
		return;
	}
	if (bst_tls_early_active(c->env.t)) {
		const bst_cfg_server *ch = chosen != NULL ? chosen : s->s.server;
		const bst_cfg_tls_profile *pf = ch->tls.profile;
		if (pf == NULL || !pf->early_data || (pf->early_methods & (1u << rq->head.method)) == 0) {
			reject(s, 425);
			return;
		}
		rq->early_data = true;
	}
	const bst_cfg_common *cfg = s->s.cfg;
	if (rq->framing.kind == BST_FRAMING_LENGTH && cfg->client_max_body_size != 0 &&
	    rq->framing.length > cfg->client_max_body_size) {
		reject(s, 413);
		return;
	}
	if (c->env.w != NULL) {
		size_t charge = sizeof *s + ARENA_CHUNK;
		if (bst_overloaded(c->env.w) || !bst_worker_mem_charge(c->env.w, charge)) {
			bst_worker_refused(c->env.w);
			reject_retry_after(s, (int)bst_worker_limits(c->env.w)->overload_status);
			return;
		}
		s->charged = charge;
	}
	bst_stream_dispatch(&s->s);
}

/* ---- nghttp3 callbacks ---- */

static int cb_begin_headers(nghttp3_conn *conn, int64_t sid, void *cud, void *sud)
{
	(void)sud;
	bst_h3_conn *c = cud;
	h3s *s = stream_new(c, sid);
	if (s == NULL)
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	(void)nghttp3_conn_set_stream_user_data(conn, sid, s);
	return 0;
}

static int cb_begin_trailers(nghttp3_conn *conn, int64_t sid, void *cud, void *sud)
{
	(void)conn, (void)sid, (void)cud;
	h3s *s = sud;
	if (s != NULL) {
		s->in_trailers = true;
		s->field_bytes = 0;
	}
	return 0;
}

static int cb_header(nghttp3_conn *conn, int64_t sid, int32_t token, nghttp3_rcbuf *name,
		     nghttp3_rcbuf *value, uint8_t flags, void *cud, void *sud)
{
	(void)conn, (void)sid, (void)token, (void)flags;
	bst_h3_conn *c = cud;
	h3s *s = sud;
	if (s == NULL || s->dead)
		return 0;
	nghttp3_vec n = nghttp3_rcbuf_get_buf(name), v = nghttp3_rcbuf_get_buf(value);
	s->field_bytes += n.len + v.len + 32; /* RFC 9114 section 4.2.2 */
	if (s->field_bytes > c->env.cfg->h3_max_field_section_size)
		s->too_large = true;
	if (s->too_large || s->field_oom)
		return 0;
	char *np = bst_arena_alloc(s->s.arena, n.len + 1), *vp = bst_arena_alloc(s->s.arena, v.len + 1);
	if (np == NULL || vp == NULL) {
		s->field_oom = true;
		return 0;
	}
	memcpy(np, n.base, n.len);
	np[n.len] = '\0';
	memcpy(vp, v.base, v.len);
	vp[v.len] = '\0';
	if (bst_headers_add(s->in_trailers ? &s->trailers : &s->fields, (bst_str){ np, (uint32_t)n.len },
			    (bst_str){ vp, (uint32_t)v.len }) != 0)
		s->field_oom = true;
	return 0;
}

static int cb_end_headers(nghttp3_conn *conn, int64_t sid, int fin, void *cud, void *sud)
{
	(void)conn, (void)sid, (void)cud;
	h3s *s = sud;
	if (s != NULL && !s->dead)
		request_start(s, fin != 0);
	return 0;
}

static int cb_end_trailers(nghttp3_conn *conn, int64_t sid, int fin, void *cud, void *sud)
{
	(void)conn, (void)sid, (void)cud, (void)fin;
	h3s *s = sud;
	if (s == NULL || s->dead)
		return 0;
	if (s->too_large || s->field_oom || !bst_validate_trailer_fields(&s->trailers))
		abort_stream(s, BST_H3_MESSAGE_ERROR, BST_STREAM_ERR_PROTOCOL);
	return 0;
}

static int cb_recv_data(nghttp3_conn *conn, int64_t sid, const uint8_t *data, size_t len, void *cud,
			void *sud)
{
	(void)conn;
	bst_h3_conn *c = cud;
	h3s *s = sud;
	if (s == NULL || s->dead || s->rejected || s->detached) {
		credit(c, sid, len); /* nobody wants it: the client may send on */
		return 0;
	}
	s->body_seen += len;
	const bst_cfg_common *cfg = s->s.cfg;
	if (cfg->client_max_body_size != 0 && s->body_seen > cfg->client_max_body_size) {
		credit(c, sid, len);
		if (!s->head_sent && s->s.handler == NULL) {
			reject(s, 413);
		} else {
			abort_stream(s, BST_H3_REQUEST_REJECTED, BST_STREAM_ERR_PROTOCOL);
		}
		return 0;
	}
	bst_buf *b = bst_buf_new(len);
	if (b == NULL)
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	memcpy(b->data, data, len);
	b->len = len;
	int rc = bst_chain_add_mem(&s->in, b, 0, len);
	bst_buf_unref(b);
	if (rc != 0)
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	deliver(s);
	return 0;
}

static int cb_deferred_consume(nghttp3_conn *conn, int64_t sid, size_t n, void *cud, void *sud)
{
	(void)conn, (void)sud;
	credit(cud, sid, n);
	return 0;
}

static int cb_end_stream(nghttp3_conn *conn, int64_t sid, void *cud, void *sud)
{
	(void)conn, (void)sid, (void)cud;
	h3s *s = sud;
	if (s != NULL && !s->dead) {
		s->remote_closed = true;
		deliver(s);
	}
	return 0;
}

static int cb_acked(nghttp3_conn *conn, int64_t sid, uint64_t n, void *cud, void *sud)
{
	(void)conn, (void)sid, (void)cud;
	h3s *s = sud;
	if (s == NULL)
		return 0;
	bst_chain_consume(&s->flight, n);
	if (s->dead)
		return 0;
	if (stage(s) != 0) {
		abort_stream(s, BST_H3_INTERNAL_ERROR, BST_STREAM_ERR_INTERNAL);
		return 0;
	}
	unblock(s);
	check_cb(s);
	return 0;
}

static int cb_stream_close(nghttp3_conn *conn, int64_t sid, uint64_t code, void *cud, void *sud)
{
	(void)conn, (void)code, (void)sid;
	bst_h3_conn *c = cud;
	h3s *s = sud;
	if (s == NULL)
		return 0;
	if (!s->dead)
		kill(s, s->resp_done ? BST_STREAM_ERR_NONE : BST_STREAM_ERR_CANCEL);
	free_stream(s);
	if (c->draining && c->nstreams == 0)
		kick(c);
	return 0;
}

/* nghttp3 asks for STOP_SENDING (or RESET_STREAM) itself: a stream error it found. */
static int cb_stop_sending(nghttp3_conn *conn, int64_t sid, uint64_t code, void *cud, void *sud)
{
	(void)conn, (void)sud;
	bst_h3_conn *c = cud;
	(void)ngtcp2_conn_shutdown_stream_read(c->env.q, 0, sid, code);
	return 0;
}

static int cb_reset_stream(nghttp3_conn *conn, int64_t sid, uint64_t code, void *cud, void *sud)
{
	(void)conn;
	bst_h3_conn *c = cud;
	h3s *s = sud;
	if (s != NULL && !s->dead)
		kill(s, BST_STREAM_ERR_PROTOCOL);
	(void)ngtcp2_conn_shutdown_stream_write(c->env.q, 0, sid, code);
	return 0;
}

static void cb_rand(uint8_t *dest, size_t len)
{
	if (RAND_bytes(dest, (int)len) != 1)
		memset(dest, 0, len);
}

/* ---- the connection ---- */

static void on_kick(void *ud)
{
	bst_h3_conn *c = ud;
	if (c->aborts_due) {
		c->aborts_due = false;
		for (h3s *s = c->streams; s != NULL; s = s->next) {
			if (s->stop_due && s->abort_code == 0) {
				s->stop_due = false;
				(void)nghttp3_conn_shutdown_stream_read(c->h3, s->id);
				(void)ngtcp2_conn_shutdown_stream_read(c->env.q, 0, s->id, BST_H3_NO_ERROR);
			}
			if (s->abort_code != 0) {
				uint64_t code = s->abort_code;
				s->abort_code = 0;
				nghttp3_conn_shutdown_stream_write(c->h3, s->id);
				(void)nghttp3_conn_shutdown_stream_read(c->h3, s->id);
				(void)ngtcp2_conn_shutdown_stream(c->env.q, 0, s->id, code);
			}
		}
	}
	/* send_body callbacks: each may give more, or end the stream */
	while (c->due != NULL) {
		h3s *s = c->due;
		c->due = s->dnext;
		s->in_due = false;
		bst_done_cb cb = s->cb;
		s->cb = NULL;
		if (cb != NULL && !s->dead)
			cb(s->cb_ud, s->cb_bytes, 0);
	}
	if (c->close_due || (c->draining && c->nstreams == 0)) {
		c->env.fail(c->env.ud, BST_H3_NO_ERROR); /* may free c */
		return;
	}
	c->env.write(c->env.ud); /* may free c */
}

bst_h3_conn *bst_h3_conn_new(const bst_h3_env *env)
{
	if (ngtcp2_conn_get_streams_uni_left(env->q) < 3) {
		bst_log(BST_LOG_DEBUG, "h3: the client allows fewer than 3 unidirectional streams");
		return NULL;
	}
	bst_h3_conn *c = calloc(1, sizeof *c);
	if (c == NULL)
		return NULL;
	c->env = *env;
	bst_timer_init(&c->t_kick);
	nghttp3_callbacks cb = {
		.acked_stream_data = cb_acked,
		.stream_close = cb_stream_close,
		.recv_data = cb_recv_data,
		.deferred_consume = cb_deferred_consume,
		.begin_headers = cb_begin_headers,
		.recv_header = cb_header,
		.end_headers = cb_end_headers,
		.begin_trailers = cb_begin_trailers,
		.recv_trailer = cb_header,
		.end_trailers = cb_end_trailers,
		.stop_sending = cb_stop_sending,
		.end_stream = cb_end_stream,
		.reset_stream = cb_reset_stream,
		.rand = cb_rand,
	};
	nghttp3_settings st;
	nghttp3_settings_default(&st);
	st.max_field_section_size = env->cfg->h3_max_field_section_size;
	st.qpack_max_dtable_capacity = (size_t)env->cfg->h3_qpack_table_size;
	st.qpack_blocked_streams = (size_t)env->cfg->h3_qpack_blocked_streams;
	if (nghttp3_conn_server_new(&c->h3, &cb, &st, NULL, c) != 0) {
		free(c);
		return NULL;
	}
	const ngtcp2_transport_params *lp = ngtcp2_conn_get_local_transport_params(env->q);
	nghttp3_conn_set_max_client_streams_bidi(c->h3, lp->initial_max_streams_bidi);
	int64_t ctrl, qenc, qdec;
	if (ngtcp2_conn_open_uni_stream(env->q, &ctrl, NULL) != 0 ||
	    nghttp3_conn_bind_control_stream(c->h3, ctrl) != 0 ||
	    ngtcp2_conn_open_uni_stream(env->q, &qenc, NULL) != 0 ||
	    ngtcp2_conn_open_uni_stream(env->q, &qdec, NULL) != 0 ||
	    nghttp3_conn_bind_qpack_streams(c->h3, qenc, qdec) != 0) {
		nghttp3_conn_del(c->h3);
		free(c);
		return NULL;
	}
	return c;
}

void bst_h3_conn_free(bst_h3_conn *c)
{
	if (c == NULL)
		return;
	bst_timer_cancel(&c->t_kick);
	while (c->streams != NULL) {
		h3s *s = c->streams;
		if (!s->dead)
			kill(s, s->resp_done ? BST_STREAM_ERR_NONE : BST_STREAM_ERR_CANCEL);
		free_stream(s);
	}
	nghttp3_conn_del(c->h3);
	free(c);
}

nghttp3_conn *bst_h3_nghttp3(bst_h3_conn *c)
{
	return c->h3;
}

int bst_h3_recv(bst_h3_conn *c, int64_t sid, const uint8_t *data, size_t len, bool fin)
{
	nghttp3_ssize n = nghttp3_conn_read_stream2(c->h3, sid, data, len, fin ? 1 : 0, now_ns());
	if (n < 0 && !nghttp3_err_is_fatal((int)n) && ngtcp2_is_bidi_stream(sid)) {
		/* A malformed request (nghttp3's own field and message checks, RFC 9114 section 4.1.2):
		 * a stream error H3_MESSAGE_ERROR, the connection goes on. */
		bst_log(BST_LOG_DEBUG, "h3: stream %lld: %s", (long long)sid, nghttp3_strerror((int)n));
		h3s *s = find(c, sid);
		if (s != NULL)
			kill(s, BST_STREAM_ERR_PROTOCOL);
		nghttp3_conn_shutdown_stream_write(c->h3, sid);
		(void)nghttp3_conn_shutdown_stream_read(c->h3, sid);
		(void)ngtcp2_conn_shutdown_stream(c->env.q, 0, sid, BST_H3_MESSAGE_ERROR);
		credit(c, sid, len);
		return 0;
	}
	if (n < 0) {
		bst_log(BST_LOG_DEBUG, "h3: read stream %lld: %s", (long long)sid, nghttp3_strerror((int)n));
		return (int)n;
	}
	credit(c, sid, (uint64_t)n);
	return 0;
}

int bst_h3_acked(bst_h3_conn *c, int64_t sid, uint64_t n)
{
	return nghttp3_conn_add_ack_offset(c->h3, sid, n);
}

int bst_h3_stream_closed(bst_h3_conn *c, int64_t sid, uint64_t app_code)
{
	int rv = nghttp3_conn_close_stream(c->h3, sid, app_code);
	if (rv == NGHTTP3_ERR_STREAM_NOT_FOUND)
		return 0;
	return rv;
}

int bst_h3_peer_reset(bst_h3_conn *c, int64_t sid)
{
	h3s *s = find(c, sid);
	if (s != NULL && !s->dead && !s->remote_closed && !s->resp_done)
		kill(s, BST_STREAM_ERR_CANCEL); /* the request will never be complete */
	return nghttp3_conn_shutdown_stream_read(c->h3, sid);
}

int bst_h3_peer_stop_sending(bst_h3_conn *c, int64_t sid)
{
	h3s *s = find(c, sid);
	if (s != NULL && !s->dead) {
		/* the response can never arrive: the handler stops (on_reset exactly once) */
		kill(s, s->resp_done ? BST_STREAM_ERR_NONE : BST_STREAM_ERR_CANCEL);
		nghttp3_conn_shutdown_stream_write(c->h3, sid);
	}
	return nghttp3_conn_shutdown_stream_read(c->h3, sid);
}

int bst_h3_max_streams(bst_h3_conn *c, uint64_t n)
{
	nghttp3_conn_set_max_client_streams_bidi(c->h3, n);
	return 0;
}

int bst_h3_unblock(bst_h3_conn *c, int64_t sid)
{
	return nghttp3_conn_unblock_stream(c->h3, sid);
}

void bst_h3_handshake_done(bst_h3_conn *c)
{
	(void)c;
}

void bst_h3_drain(bst_h3_conn *c)
{
	if (c->draining)
		return;
	c->draining = true;
	(void)nghttp3_conn_submit_shutdown_notice(c->h3);
	(void)nghttp3_conn_shutdown(c->h3);
	kick(c);
}

bool bst_h3_drained(const bst_h3_conn *c)
{
	return c->draining && c->nstreams == 0;
}

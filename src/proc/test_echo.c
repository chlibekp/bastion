/* See test_hooks.h (bst_test_echo_handler). */
#ifdef BST_TEST
#include "core/buf.h"
#include "core/chain.h"
#include "core/log.h"
#include "http/stream.h"
#include "proc/test_hooks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CREDIT (256u * 1024u)
#define GEN_CHUNK (64u * 1024u)

typedef struct echo {
	bst_chain pend;		 /* request body taken, not yet sent back */
	bool sending, end_seen, end_sent;
	uint64_t gen_left;	 /* bytes still to generate (GET) */
	uint64_t gen_off;
	bool want_trailers;
	bst_headers trl;	 /* request trailers, sent back with an x-echo- prefix */
} echo;

static bst_buf *g_pattern; /* GEN_CHUNK bytes of (i*31+7) & 0xff, the h3client body pattern */

static const bst_header *hdr(bst_stream *s, const char *name)
{
	return bst_headers_get_name(&s->req.head.headers, (bst_str){ name, (uint32_t)strlen(name) });
}

static void finish(bst_stream *s, echo *e)
{
	if (e->trl.n > 0 || e->want_trailers) {
		bst_headers out;
		bst_headers_init(&out, s->arena);
		for (uint32_t i = 0; i < e->trl.n; i++) {
			char *n = bst_arena_alloc(s->arena, e->trl.v[i].name.len + 8u);
			if (n == NULL)
				break;
			int k = snprintf(n, e->trl.v[i].name.len + 8u, "x-echo-%.*s", (int)e->trl.v[i].name.len,
					 e->trl.v[i].name.p);
			(void)bst_headers_add(&out, (bst_str){ n, (uint32_t)k }, e->trl.v[i].value);
		}
		if (out.n == 0)
			(void)bst_headers_add(&out, BST_S("x-echo-trailer"), BST_S("done"));
		(void)bst_stream_send_trailers(s, &out);
	}
}

static void pump(bst_stream *s, echo *e);

static void on_sent(void *ud, size_t bytes, int err)
{
	(void)bytes;
	bst_stream *s = ud;
	echo *e = s->hctx;
	e->sending = false;
	if (err != 0 || e->end_sent)
		return;
	pump(s, e);
}

static void pump(bst_stream *s, echo *e)
{
	if (e->sending || e->end_sent)
		return;
	bool trailers = e->trl.n > 0 || e->want_trailers;
	if (e->gen_left > 0) {
		size_t n = e->gen_left < GEN_CHUNK ? (size_t)e->gen_left : GEN_CHUNK;
		bst_chain c;
		bst_chain_init(&c, s->chain_slab);
		if (bst_chain_add_mem(&c, g_pattern, 0, n) != 0) {
			s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
			return;
		}
		e->gen_left -= n;
		bool end = e->gen_left == 0 && !trailers;
		e->sending = true;
		e->end_sent = e->gen_left == 0;
		if (bst_stream_send_body(s, &c, end, on_sent, s) != 0) {
			bst_chain_clear(&c);
			return;
		}
		if (e->end_sent)
			finish(s, e);
		return;
	}
	if (e->pend.len > 0 || e->end_seen) {
		bool end = e->end_seen && !trailers;
		e->sending = true;
		e->end_sent = e->end_seen;
		if (bst_stream_send_body(s, &e->pend, end, on_sent, s) != 0)
			return;
		if (e->end_sent)
			finish(s, e);
		return;
	}
	bst_stream_read_body(s, CREDIT);
}

static void on_request(bst_stream *s)
{
	echo *e = bst_arena_alloc(s->arena, sizeof *e);
	if (e == NULL) {
		(void)bst_send_error(s, 500);
		return;
	}
	memset(e, 0, sizeof *e);
	bst_chain_init(&e->pend, s->chain_slab);
	bst_headers_init(&e->trl, s->arena);
	s->hctx = e;
	const bst_header *g = hdr(s, "x-gen"), *t = hdr(s, "x-want-trailers");
	e->want_trailers = t != NULL;
	bst_resp_head h = { .status = 200, .content_length = -1 };
	bst_headers_init(&h.headers, s->arena);
	(void)bst_headers_add(&h.headers, BST_S("content-type"), BST_S("application/octet-stream"));
	if (g != NULL) {
		e->gen_left = strtoull(g->value.p, NULL, 10);
		if (g_pattern == NULL && (g_pattern = bst_buf_new(GEN_CHUNK)) != NULL) {
			for (size_t i = 0; i < GEN_CHUNK; i++)
				g_pattern->data[i] = (unsigned char)((i * 31 + 7) & 0xff);
			g_pattern->len = GEN_CHUNK;
		}
		if (g_pattern == NULL) {
			(void)bst_send_error(s, 500);
			return;
		}
		h.content_length = e->want_trailers ? -1 : (int64_t)e->gen_left;
	} else if (s->req.framing.kind == BST_FRAMING_LENGTH && !e->want_trailers) {
		h.content_length = (int64_t)s->req.framing.length;
	} else if (s->req.framing.kind == BST_FRAMING_NONE) {
		e->end_seen = true;
		h.content_length = e->want_trailers ? -1 : 0;
	}
	if (bst_stream_send_head(s, &h, false) != 0)
		return;
	pump(s, e);
}

static void on_body(bst_stream *s, bst_chain *c, bool end)
{
	echo *e = s->hctx;
	if (bst_chain_move(&e->pend, c) != 0) {
		s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
		return;
	}
	e->end_seen = end;
	pump(s, e);
}

static void on_trailers(bst_stream *s, const bst_headers *t)
{
	echo *e = s->hctx;
	for (uint32_t i = 0; i < t->n; i++)
		(void)bst_headers_add(&e->trl, t->v[i].name, t->v[i].value);
}

static void on_reset(bst_stream *s, bst_stream_err why)
{
	echo *e = s->hctx;
	if (e != NULL)
		bst_chain_clear(&e->pend);
	bst_log(BST_LOG_INFO, "test-echo: on_reset why=%d uri=%.*s", (int)why, (int)s->uri.len, s->uri.p);
}

const bst_handler_ops bst_test_echo_handler = {
	.on_request = on_request,
	.on_body = on_body,
	.on_trailers = on_trailers,
	.on_reset = on_reset,
};

bool bst_test_echo_wants(const bst_stream *s)
{
	static int on = -1;
	if (on < 0)
		on = getenv("BST_TEST_ECHO") != NULL;
	return on && s->uri.len >= 5 && memcmp(s->uri.p, "/echo", 5) == 0;
}
#endif

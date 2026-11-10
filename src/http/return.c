/* The built-in `return` handler: a fixed status, with the text as the body (or as the Location of
 * a redirect). It reads and discards the request body first, so a keep-alive connection stays
 * usable, and so `Expect: 100-continue` gets its 100. */
#include "http/stream.h"
#include "proc/worker.h"

#include <stdlib.h>
#include <string.h>

typedef struct rctx {
	bst_timer delay; /* test builds only: X-Bst-Test-Delay: <ms> holds the answer back */
	bool armed;
} rctx;

static bool is_redirect(unsigned st)
{
	return st == 301 || st == 302 || st == 303 || st == 307 || st == 308;
}

static void respond(bst_stream *s)
{
	const bst_cfg_return *r = &s->cfg->http.ret;
	int st = (int)r->status;
	if (is_redirect(r->status) && r->text != NULL) {
		(void)bst_send_error_hdr(s, st, BST_S("Location"),
					 (bst_str){ r->text, (uint32_t)strlen(r->text) });
		return;
	}
	if (r->text == NULL && st >= 400) {
		(void)bst_send_error(s, st);
		return;
	}
	bool body = st != 204 && st != 304;
	size_t n = (r->text != NULL && body) ? strlen(r->text) : 0;
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = st;
	h.content_length = body ? (int64_t)n : -1;
	bst_headers_init(&h.headers, s->arena);
	if (n > 0 && bst_headers_add(&h.headers, BST_S("Content-Type"), BST_S("text/plain; charset=utf-8")) != 0)
		return;
	if (bst_stream_send_head(s, &h, n == 0) != 0 || n == 0)
		return;
	bst_buf *b = bst_buf_new(n);
	if (b == NULL)
		return;
	memcpy(b->data, r->text, n);
	b->len = n;
	bst_chain *c = bst_arena_alloc(s->arena, sizeof *c);
	if (c != NULL) {
		bst_chain_init(c, s->chain_slab);
		if (bst_chain_add_mem(c, b, 0, n) == 0)
			(void)bst_stream_send_body(s, c, true, NULL, NULL);
	}
	bst_buf_unref(b);
}

#ifdef BST_TEST
static void delayed(void *ud)
{
	bst_stream *s = ud;
	((rctx *)s->hctx)->armed = false;
	respond(s);
}
#endif

static void finish(bst_stream *s)
{
#ifdef BST_TEST
	const bst_header *d = bst_headers_get_name(&s->req.head.headers, BST_S("x-bst-test-delay"));
	if (d != NULL) {
		uint64_t ms = 0;
		if (bst_str_to_u64(d->value, &ms) && ms > 0) {
			rctx *c = s->hctx;
			c->armed = true;
			bst_loop_timer_arm(bst_worker_loop(s->worker), &c->delay, ms, delayed, s);
			return;
		}
	}
#endif
	respond(s);
}

static void on_request(bst_stream *s)
{
	rctx *c = bst_arena_alloc(s->arena, sizeof *c);
	if (c == NULL) {
		(void)bst_send_error(s, 500);
		return;
	}
	bst_timer_init(&c->delay);
	c->armed = false;
	s->hctx = c;
	if (s->req.framing.kind == BST_FRAMING_NONE)
		finish(s);
	else
		bst_stream_read_body(s, SIZE_MAX);
}

static void on_body(bst_stream *s, bst_chain *in, bool end)
{
	bst_chain_clear(in);
	if (end)
		finish(s);
}

static void on_reset(bst_stream *s, bst_stream_err why)
{
	(void)why;
	rctx *c = s->hctx;
	if (c != NULL)
		bst_timer_cancel(&c->delay);
}

const bst_handler_ops bst_return_handler = {
	.on_request = on_request,
	.on_body = on_body,
	.on_reset = on_reset,
};

/* See auth_common.h. */
#include "auth/auth_common.h"

#include "core/buf.h"
#include "core/log.h"

#include <string.h>

typedef enum mech { MECH_MTLS = 0, MECH_JWT, MECH_BASIC, MECH_FORWARD, MECH_COUNT_ } mech;

struct bst_auth_run {
	bst_stream *s;
	bst_auth_done_cb cb;
	bool dead;	 /* the stream ended: nothing may touch it */
	bool all;	 /* auth_require all */
	mech mechs[MECH_COUNT_];
	int n, i;
	bool have_deny;
	int deny_status;
	bst_str deny_name, deny_val;
	void (*cancel)(void *);
	void *pending;
	const bst_headers *resp_h; /* a whole denial response (forward auth) */
	bst_buf *resp_body;
};

static void (*const starts[MECH_COUNT_])(bst_auth_run *) = {
	[MECH_MTLS] = bst_auth_mtls_start,
	[MECH_JWT] = bst_auth_jwt_start,
	[MECH_BASIC] = bst_auth_basic_start,
	[MECH_FORWARD] = bst_auth_forward_start,
};

static int collect(const bst_stream *s, mech out[MECH_COUNT_])
{
	const bst_cfg_auth *a = &s->cfg->auth;
	int n = 0;
	if (bst_auth_mtls_configured(s))
		out[n++] = MECH_MTLS;
	if (a->jwt != NULL)
		out[n++] = MECH_JWT;
	if (a->basic_realm != NULL)
		out[n++] = MECH_BASIC;
	if (a->forward != NULL)
		out[n++] = MECH_FORWARD;
	return n;
}

bool bst_auth_required(const bst_stream *s)
{
	mech m[MECH_COUNT_];
	return collect(s, m) > 0;
}

bst_stream *bst_auth_stream(bst_auth_run *r)
{
	return r->s;
}

void bst_auth_set_pending(bst_auth_run *r, void (*cancel)(void *), void *pending)
{
	r->cancel = cancel;
	r->pending = pending;
}

/* The placeholder handler while a mechanism runs: only on_reset can come (no body credit was
 * given), and it cancels the work. */
static void wait_request(bst_stream *s)
{
	(void)s;
}

static void wait_body(bst_stream *s, bst_chain *c, bool end)
{
	(void)s, (void)end;
	bst_chain_clear(c);
}

static void wait_reset(bst_stream *s, bst_stream_err why)
{
	(void)why;
	bst_auth_run *r = s->hctx;
	if (r == NULL)
		return;
	r->dead = true;
	r->s = NULL;
	if (r->cancel != NULL)
		r->cancel(r->pending);
	r->cancel = NULL;
	r->pending = NULL;
}

static const bst_handler_ops wait_ops = {
	.on_request = wait_request,
	.on_body = wait_body,
	.on_reset = wait_reset,
};

static void finish(bst_auth_run *r, int status, bst_str hn, bst_str hv)
{
	bst_stream *s = r->s;
	s->handler = NULL;
	s->hctx = NULL;
	if (status != 0)
		s->auth_user = (bst_str){ NULL, 0 };
	if (status != 0 && r->resp_h != NULL && r->deny_status == status) {
		bst_resp_head h;
		memset(&h, 0, sizeof h);
		h.status = status;
		h.headers = *r->resp_h;
		size_t bl = r->resp_body ? r->resp_body->len : 0;
		h.content_length = (int64_t)bl;
		bst_buf *b = r->resp_body;
		r->resp_body = NULL;
		if (bst_stream_send_head(s, &h, bl == 0) == 0 && bl > 0) {
			bst_chain c;
			bst_chain_init(&c, s->chain_slab);
			if (bst_chain_add_mem(&c, b, 0, bl) != 0 ||
			    bst_stream_send_body(s, &c, true, NULL, NULL) != 0)
				s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
		}
		bst_buf_unref(b);
		return;
	}
	bst_buf_unref(r->resp_body);
	r->resp_body = NULL;
	r->cb(s, status, hn, hv);
}

void bst_auth_deny_response(bst_auth_run *r, int status, const bst_headers *h, bst_buf *body)
{
	if (r->dead) {
		bst_buf_unref(body);
		return;
	}
	if (!r->have_deny || r->all) { /* this denial is the one answered */
		bst_buf_unref(r->resp_body);
		r->resp_h = h;
		r->resp_body = body;
	} else {
		bst_buf_unref(body);
	}
	bst_auth_step(r, status, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
}

static void run_next(bst_auth_run *r)
{
	if (r->i >= r->n) {
		if (r->all && !r->have_deny)
			finish(r, 0, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
		else
			finish(r, r->have_deny ? r->deny_status : 401, r->deny_name, r->deny_val);
		return;
	}
	starts[r->mechs[r->i]](r);
}

void bst_auth_step(bst_auth_run *r, int status, bst_str hname, bst_str hval)
{
	r->cancel = NULL;
	r->pending = NULL;
	if (r->dead)
		return; /* the stream is gone: the run is freed with its arena */
	if (status == 0 && !r->all) {
		finish(r, 0, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
		return;
	}
	if (status != 0) {
		if (!r->have_deny || (r->deny_status < 500 && status >= 500)) {
			/* the first denial; an overload or internal failure outranks it, so a
			 * client is told to come back rather than that its credentials failed */
			r->have_deny = true;
			r->deny_status = status;
			r->deny_name = hname;
			r->deny_val = hval;
		}
		if (r->all) {
			finish(r, r->deny_status, r->deny_name, r->deny_val);
			return;
		}
	}
	r->i++;
	run_next(r);
}

void bst_auth_check(bst_stream *s, bst_auth_done_cb cb)
{
	bst_auth_run *r = bst_arena_alloc(s->arena, sizeof *r);
	if (r == NULL) {
		cb(s, 500, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
		return;
	}
	memset(r, 0, sizeof *r);
	r->s = s;
	r->cb = cb;
	r->all = s->cfg->auth.require_all;
	r->n = collect(s, r->mechs);
	s->auth_user = (bst_str){ NULL, 0 };
	s->handler = &wait_ops;
	s->hctx = r;
	run_next(r);
}

/* See forward.h. Also its directive. */
#include "auth/forward.h"

#include "auth/auth_common.h"
#include "config/compile.h"
#include "config/values.h"
#include "core/buf.h"
#include "core/log.h"
#include "filters/extras.h"
#include "io/loop.h"
#include "proc/worker.h"
#include "proxy/balance.h"
#include "proxy/client_h1.h"
#include "proxy/pool.h"
#include "proxy/upstream.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define BODY_MAX 65536 /* the most of a denial's body passed back to the client */

static const char *const original[] = { "X-Original-Method", "X-Original-URI", "X-Original-Host",
					"X-Original-Proto" };

typedef struct fjob {
	bst_auth_run *r;
	bst_stream *s;
	const bst_fwd_cfg *fc;
	bst_loop *loop;
	bst_upconn *uc;
	bst_timer t;
	bool timer_on;
	bst_h1_client rc;
	bool rc_init;
	int status;
	bst_buf *body;	/* a denial's body, collected */
	bool done;
	bst_chain out;	/* the request head being sent: the send holds it until done */
	bool out_init;
} fjob;

static void job_end(fjob *j)
{
	if (j->timer_on)
		bst_timer_cancel(&j->t);
	j->timer_on = false;
	if (j->uc != NULL)
		bst_pool_close(j->uc); /* never reused: one exchange per connection, simple and safe */
	j->uc = NULL;
	if (j->rc_init)
		bst_h1_client_free(&j->rc);
	j->rc_init = false;
	bst_buf_unref(j->body);
	j->body = NULL;
	if (j->out_init)
		bst_chain_clear(&j->out);
	free(j);
}

/* The verdict; the job is gone afterwards. */
static void verdict(fjob *j, int status)
{
	bst_auth_run *r = j->r;
	if (j->done)
		return;
	j->done = true;
	bst_stream *s = j->s;
	if (status >= 200 && status < 300) {
		bst_headers *rq = &s->req.head.headers;
		for (size_t i = 0; i < j->fc->nresp; i++) {
			bst_str n = { j->fc->resp[i], (uint32_t)strlen(j->fc->resp[i]) };
			for (const bst_header *h = bst_headers_next_name(&j->rc.head.headers, NULL, n); h != NULL;
			     h = bst_headers_next_name(&j->rc.head.headers, h, n)) {
				char *v = bst_arena_alloc(s->arena, h->value.len + 1);
				if (v == NULL)
					continue;
				memcpy(v, h->value.p, h->value.len);
				(void)bst_headers_add(rq, n, (bst_str){ v, h->value.len });
			}
		}
		job_end(j);
		bst_auth_step(r, 0, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
		return;
	}
	if (status == 401 || status == 403 || (status >= 300 && status < 400)) {
		/* the service's own answer, with the fields a client needs to act on it */
		static const char *const keep[] = { "Location", "WWW-Authenticate", "Content-Type",
						    "Set-Cookie", "Cache-Control" };
		bst_headers *out = bst_arena_alloc(s->arena, sizeof *out);
		if (out == NULL) {
			job_end(j);
			bst_auth_step(r, 503, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
			return;
		}
		bst_headers_init(out, s->arena);
		for (size_t i = 0; i < sizeof keep / sizeof keep[0]; i++) {
			bst_str n = { keep[i], (uint32_t)strlen(keep[i]) };
			for (const bst_header *h = bst_headers_next_name(&j->rc.head.headers, NULL, n); h != NULL;
			     h = bst_headers_next_name(&j->rc.head.headers, h, n)) {
				char *v = bst_arena_alloc(s->arena, h->value.len + 1);
				if (v != NULL) {
					memcpy(v, h->value.p, h->value.len);
					(void)bst_headers_add(out, n, (bst_str){ v, h->value.len });
				}
			}
		}
		bst_buf *b = j->body;
		j->body = NULL;
		job_end(j);
		bst_auth_deny_response(r, status, out, b);
		return;
	}
	job_end(j);
	bst_auth_step(r, 503, BST_S("Retry-After"), BST_S("5")); /* fails closed */
}

static void cancel(void *p)
{
	fjob *j = p;
	j->done = true;
	job_end(j);
}

static void on_timeout(void *ud)
{
	fjob *j = ud;
	j->timer_on = false;
	bst_log(BST_LOG_WARN, "auth_forward %s: no answer in time: 503", j->fc->upstream);
	verdict(j, 503);
}

static bool keep_body(fjob *j, const bst_chain *c)
{
	if (j->status >= 200 && j->status < 300)
		return true; /* discarded */
	struct iovec iov[32];
	int n = bst_chain_to_iov(c, iov, 32);
	for (int i = 0; i < n; i++) {
		size_t have = j->body ? j->body->len : 0;
		if (have + iov[i].iov_len > BODY_MAX)
			return false;
		if (j->body == NULL && (j->body = bst_buf_new(BODY_MAX)) == NULL)
			return false;
		memcpy(j->body->data + have, iov[i].iov_base, iov[i].iov_len);
		j->body->len = have + iov[i].iov_len;
	}
	return true;
}

static void on_recv(void *ud, bst_buf *b, int err)
{
	fjob *j = ud;
	if (b == NULL) {
		if (err == 0 && bst_h1_client_eof(&j->rc) == BST_UPC_DONE)
			verdict(j, j->status);
		else
			verdict(j, 503);
		return;
	}
	size_t off = 0;
	bst_chain body;
	bst_chain_init(&body, j->s->chain_slab);
	for (;;) {
		bst_upc_ev ev = bst_h1_client_feed(&j->rc, b, &off, &body);
		if (ev == BST_UPC_INTERIM)
			continue;
		if (ev == BST_UPC_HEAD) {
			j->status = j->rc.head.status;
			continue;
		}
		if (ev == BST_UPC_BODY || ev == BST_UPC_MORE || ev == BST_UPC_DONE) {
			bool ok = keep_body(j, &body);
			bst_chain_clear(&body);
			if (!ok) {
				bst_buf_unref(b);
				verdict(j, 503);
				return;
			}
			if (ev == BST_UPC_DONE) {
				bst_buf_unref(b);
				verdict(j, j->status);
				return;
			}
			if (ev == BST_UPC_MORE)
				break;
			continue;
		}
		bst_chain_clear(&body);
		bst_buf_unref(b);
		bst_log(BST_LOG_WARN, "auth_forward %s: malformed answer: 503", j->fc->upstream);
		verdict(j, 503);
		return;
	}
	bst_chain_clear(&body);
	bst_buf_unref(b);
}

static void sent(void *ud, size_t n, int err)
{
	fjob *j = ud;
	(void)n;
	if (err != 0 && !j->done)
		verdict(j, 503);
}

static void on_conn(void *ud, bst_upconn *c, int err)
{
	fjob *j = ud;
	if (err != 0 || c == NULL) {
		j->uc = NULL;
		bst_log(BST_LOG_WARN, "auth_forward %s: can not connect (%s): 503", j->fc->upstream,
			strerror(err < 0 ? -err : EIO));
		verdict(j, 503);
		return;
	}
	j->uc = c;
	bst_stream *s = j->s;
	bst_headers hs;
	bst_headers_init(&hs, s->arena);
	const bst_req_head *rq = &s->req.head;
	bool ok = bst_headers_add(&hs, BST_S("X-Original-Method"), rq->method_str) == 0 &&
		  bst_headers_add(&hs, BST_S("X-Original-URI"), rq->target) == 0 &&
		  bst_headers_add(&hs, BST_S("X-Original-Host"), s->req.host) == 0 &&
		  bst_headers_add(&hs, BST_S("X-Original-Proto"),
				  bst_stream_is_tls(s) ? BST_S("https") : BST_S("http")) == 0 &&
		  bst_headers_add(&hs, BST_S("Connection"), BST_S("close")) == 0;
	for (size_t i = 0; ok && i < j->fc->npass; i++) {
		bst_str n = { j->fc->pass[i], (uint32_t)strlen(j->fc->pass[i]) };
		for (const bst_header *h = bst_headers_next_name(&rq->headers, NULL, n); ok && h != NULL;
		     h = bst_headers_next_name(&rq->headers, h, n))
			ok = bst_headers_add(&hs, h->name, h->value) == 0;
	}
	const char *path = j->fc->path ? j->fc->path : "/";
	bst_h1_req_out ro = { .method = BST_S("GET"),
			      .target = { path, (uint32_t)strlen(path) },
			      .host = { j->fc->up->name, (uint32_t)strlen(j->fc->up->name) },
			      .headers = &hs,
			      .has_length = false };
	bst_buf *head = ok ? bst_h1_req_head(&ro) : NULL;
	bst_chain_init(&j->out, s->chain_slab);
	j->out_init = true;
	if (head == NULL || bst_chain_add_mem(&j->out, head, 0, head->len) != 0) {
		bst_buf_unref(head);
		verdict(j, 503);
		return;
	}
	bst_buf_unref(head);
	bst_h1_body_cfg bc = { .chunk_ext_limit = 1024, .max_trailer = 4096 };
	bst_h1_client_init(&j->rc, s->arena, 16384, false, &bc);
	j->rc_init = true;
	if (bst_upconn_send(c, &j->out, sent, j) != 0 || bst_upconn_recv_start(c, on_recv, j) != 0)
		verdict(j, 503);
}

void bst_auth_forward_start(bst_auth_run *r)
{
	bst_stream *s = bst_auth_stream(r);
	const bst_fwd_cfg *fc = s->cfg->auth.forward;
	bst_headers *rq = &s->req.head.headers;
	for (size_t i = 0; i < sizeof original / sizeof original[0]; i++) /* never spoofable */
		(void)bst_headers_remove_name(rq, (bst_str){ original[i], (uint32_t)strlen(original[i]) });
	for (size_t i = 0; i < fc->nresp; i++)
		(void)bst_headers_remove_name(rq, (bst_str){ fc->resp[i], (uint32_t)strlen(fc->resp[i]) });
	fjob *j = calloc(1, sizeof *j);
	if (j == NULL || fc->up == NULL) {
		free(j);
		bst_auth_step(r, 503, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
		return;
	}
	j->r = r;
	j->s = s;
	j->fc = fc;
	j->loop = bst_worker_loop(s->worker);
	bst_sockaddr addr;
	bst_pick_ctx pk = { .s = s };
	const bst_peer *peer = bst_balance_pick(fc->up, &pk, &addr);
	if (peer == NULL) {
		free(j);
		bst_auth_step(r, 503, BST_S("Retry-After"), BST_S("5"));
		return;
	}
	bst_auth_set_pending(r, cancel, j);
	bst_loop_timer_arm(j->loop, &j->t, fc->timeout_ms, on_timeout, j);
	j->timer_on = true;
	bst_upconn *c = NULL;
	int rc = bst_pool_get(j->loop, fc->up, peer, &addr, true, on_conn, j, &c);
	if (rc < 0) {
		verdict(j, 503);
		return;
	}
	if (rc == 1)
		on_conn(j, c, 0);
}

/* ---- directive ---- */

#define GSL (BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION)

static int list(bst_cfg_ctx *c, const bst_ast_arg *v, const char *const **out, size_t *n, bst_err *e)
{
	size_t cnt = 1;
	for (size_t i = 0; i < v->len; i++)
		cnt += v->text[i] == ',';
	const char **l = bst_arena_alloc(c->arena, cnt * sizeof *l);
	if (l == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	size_t k = 0, st = 0;
	for (size_t i = 0; i <= v->len; i++)
		if (i == v->len || v->text[i] == ',') {
			if (i > st && (l[k++] = bst_cfg_strdup(c, v->text + st, i - st, e)) == NULL)
				return -1;
			st = i + 1;
		}
	*out = l;
	*n = k;
	return 0;
}

static int ap_forward(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (a->len == 3 && memcmp(a->text, "off", 3) == 0) {
		c->common->auth.forward = NULL;
		return 0;
	}
	bst_fwd_cfg *f = bst_arena_alloc(c->arena, sizeof *f);
	if (f == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(f, 0, sizeof *f);
	if ((f->upstream = bst_cfg_strdup(c, a->text, a->len, e)) == NULL)
		return -1;
	f->timeout_ms = 5000;
	static const char *const def_pass[] = { "Authorization", "Cookie" };
	f->pass = def_pass;
	f->npass = 2;
	bst_ast_arg v;
	if (bst_dir_opt(d, n, "path=", &v) && (f->path = bst_cfg_strdup(c, v.text, v.len, e)) == NULL)
		return -1;
	if (bst_dir_opt(d, n, "timeout=", &v)) {
		uint64_t us = 0;
		(void)bst_parse_duration_us((bst_str){ v.text, (uint32_t)v.len }, &us);
		f->timeout_ms = us / 1000;
	}
	if (bst_dir_opt(d, n, "pass_headers=", &v) && list(c, &v, &f->pass, &f->npass, e) != 0)
		return -1;
	if (bst_dir_opt(d, n, "response_headers=", &v) && list(c, &v, &f->resp, &f->nresp, e) != 0)
		return -1;
	if (bst_dir_opt(d, n, "fail=", &v) && !(v.len == 6 && memcmp(v.text, "closed", 6) == 0)) {
		bst_err_set(e, "auth_forward: fail=closed is the only mode: there is no fail-open");
		bst_cfg_err_at(e, &v.loc);
		return -1;
	}
	c->common->auth.forward = f;
	return 0;
}

static int resolve(bst_config *cfg, bst_cfg_ctx *c, const bst_cfg_common *cm, bst_err *e)
{
	bst_fwd_cfg *f = (bst_fwd_cfg *)cm->auth.forward;
	(void)c;
	if (f == NULL || f->up != NULL)
		return 0;
	f->up = bst_upstream_find(&cfg->global, f->upstream, strlen(f->upstream));
	if (f->up == NULL) {
		bst_err_set(e, "auth_forward %s: no upstream with that name", f->upstream);
		return -1;
	}
	return 0;
}

static int resolve_locs(bst_config *cfg, bst_cfg_ctx *c, bst_cfg_location **ls, size_t n, bst_err *e)
{
	for (size_t i = 0; i < n; i++)
		if (resolve(cfg, c, &ls[i]->common, e) != 0 ||
		    resolve_locs(cfg, c, ls[i]->children, ls[i]->nchildren, e) != 0)
			return -1;
	return 0;
}

static int post_auth_forward(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	if (resolve(cfg, c, &cfg->global.common, e) != 0)
		return -1;
	for (size_t i = 0; i < cfg->global.nservers; i++) {
		bst_cfg_server *s = cfg->global.servers[i];
		if (resolve(cfg, c, &s->common, e) != 0 ||
		    resolve_locs(cfg, c, s->locations, s->nlocations, e) != 0)
			return -1;
	}
	return 0;
}
BST_CFG_POST(post_auth_forward);

static const bst_optspec fwd_opts[] = {
	{ .key = "path=", .type = { .kind = BST_T_STRING } },
	{ .key = "timeout=", .type = { .kind = BST_T_DURATION, .min = 1000, .max = 60ll * 1000000 } },
	{ .key = "pass_headers=", .type = { .kind = BST_T_STRING } },
	{ .key = "response_headers=", .type = { .kind = BST_T_STRING } },
	{ .key = "fail=", .type = { .kind = BST_T_STRING } },
};

static const bst_directive fwd_dirs[] = {
	{ .name = "auth_forward", .contexts = GSL, .apply = ap_forward,
	  .doc = "auth_forward <upstream> [path=/auth] [timeout=5s] [pass_headers=Authorization,"
		 "Cookie] [response_headers=X-User,..] [fail=closed], or off. Before the handler a "
		 "GET goes to the auth service with the listed request headers and X-Original-Method, "
		 "-URI, -Host and -Proto (client copies of those are removed). 2xx lets the request "
		 "in with the response_headers copied onto it (client copies removed); 401, 403 and "
		 "redirects go back to the client with their body; a timeout, refused connection or "
		 "any other answer is 503. There is no fail-open. The request body is not sent.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } }, .opts = fwd_opts,
		    .nopts = sizeof fwd_opts / sizeof fwd_opts[0] } },
};
BST_DIRECTIVES(fwd_dirs);

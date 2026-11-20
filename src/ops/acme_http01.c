/* HTTP-01 (RFC 8555 section 8.3): the job puts key authorizations in the shared table, workers
 * answer GET /.well-known/acme-challenge/<token> from it. Only a token in the table is ever
 * answered: the path is never mapped to a file, and a token is base64url only, so `..`, `/` or
 * an encoded byte can never name anything. Also the port-80 redirect of an implied `tls auto`
 * listener. */
#include "ops/acme_priv.h"

#include "core/buf.h"
#include "core/chain.h"
#include "core/log.h"
#include "core/shm.h"
#include "filters/extras.h"
#include "http/stream.h"

#include <errno.h>
#include <string.h>

bst_acme_region *bst_acme_region_;

#define PREFIX "/.well-known/acme-challenge/"

static bool any_auto(const bst_config *cfg)
{
	for (size_t i = 0; i < cfg->global.nservers; i++)
		if (cfg->global.servers[i]->tls_auto)
			return true;
	return false;
}

int bst_acme_setup(const bst_config *cfg, bst_err *err)
{
	if (cfg->global.acme == NULL || !any_auto(cfg) || bst_acme_region_ != NULL)
		return 0;
	bst_acme_region_ = bst_shm_create("bst-acme", sizeof(bst_acme_region), NULL);
	if (bst_acme_region_ == NULL) {
		bst_err_set(err, "acme: shared memory: %s", strerror(errno));
		return -1;
	}
	return 0;
}

bool bst_acme_token_valid(bst_str t)
{
	if (t.len == 0 || t.len >= BST_ACME_TOKEN_MAX)
		return false;
	for (uint32_t i = 0; i < t.len; i++) {
		char c = t.p[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
		      c == '_'))
			return false;
	}
	return true;
}

int bst_acme_http01_put(bst_str token, bst_str keyauth)
{
	bst_acme_region *r = bst_acme_region_;
	if (r == NULL || !bst_acme_token_valid(token) || keyauth.len == 0 || keyauth.len >= BST_ACME_KEYAUTH_MAX)
		return -1;
	bst_acme_tok *slot = NULL;
	for (size_t i = 0; i < BST_ACME_TOKENS; i++) {
		bst_acme_tok *t = &r->tok[i];
		uint32_t s = atomic_load_explicit(&t->seq, memory_order_relaxed);
		if (s != 0 && t->tlen == token.len && memcmp(t->token, token.p, token.len) == 0) {
			slot = t;
			break;
		}
		if (slot == NULL && s == 0)
			slot = t;
	}
	if (slot == NULL)
		return -1;
	uint32_t w = bst_acme_write_begin(&slot->seq);
	memcpy(slot->token, token.p, token.len);
	slot->tlen = (uint16_t)token.len;
	memcpy(slot->keyauth, keyauth.p, keyauth.len);
	slot->klen = (uint16_t)keyauth.len;
	bst_acme_write_end(&slot->seq, w);
	return 0;
}

void bst_acme_http01_remove(bst_str token)
{
	bst_acme_region *r = bst_acme_region_;
	if (r == NULL)
		return;
	for (size_t i = 0; i < BST_ACME_TOKENS; i++) {
		bst_acme_tok *t = &r->tok[i];
		if (atomic_load_explicit(&t->seq, memory_order_relaxed) == 0 || t->tlen != token.len ||
		    memcmp(t->token, token.p, token.len) != 0)
			continue;
		(void)bst_acme_write_begin(&t->seq);
		t->tlen = t->klen = 0;
		atomic_store_explicit(&t->seq, 0, memory_order_release);
	}
}

int bst_acme_http01_get(bst_str token, char *out, size_t cap)
{
	bst_acme_region *r = bst_acme_region_;
	if (r == NULL || !bst_acme_token_valid(token))
		return -1;
	for (size_t i = 0; i < BST_ACME_TOKENS; i++) {
		bst_acme_tok *t = &r->tok[i];
		uint32_t s1 = atomic_load_explicit(&t->seq, memory_order_acquire);
		if (s1 == 0 || (s1 & 1u))
			continue;
		char tok[BST_ACME_TOKEN_MAX];
		uint16_t tl = t->tlen, kl = t->klen;
		if (tl != token.len || kl == 0 || kl >= BST_ACME_KEYAUTH_MAX || (size_t)kl > cap)
			continue;
		memcpy(tok, t->token, tl);
		memcpy(out, t->keyauth, kl);
		atomic_thread_fence(memory_order_acquire);
		if (atomic_load_explicit(&t->seq, memory_order_relaxed) != s1)
			continue; /* rewritten meanwhile */
		if (memcmp(tok, token.p, tl) == 0)
			return kl;
	}
	return -1;
}

static int send_text(bst_stream *s, int status, const char *body, size_t len)
{
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = status;
	h.content_length = (int64_t)len;
	bst_headers_init(&h.headers, s->arena);
	if (bst_headers_add(&h.headers, BST_S("Content-Type"), BST_S("application/octet-stream")) != 0 ||
	    bst_headers_add(&h.headers, BST_S("Cache-Control"), BST_S("no-store")) != 0)
		return -1;
	bool head = s->req.head.method == BST_M_HEAD;
	if (bst_stream_send_head(s, &h, head) != 0)
		return -1;
	if (head)
		return 0;
	bst_buf *b = bst_buf_new(len);
	if (b == NULL)
		return -1;
	memcpy(b->data, body, len);
	b->len = len;
	bst_chain c;
	bst_chain_init(&c, s->chain_slab);
	int rc = bst_chain_add_mem(&c, b, 0, b->len);
	bst_buf_unref(b);
	if (rc != 0)
		return -1;
	return bst_stream_send_body(s, &c, true, NULL, NULL);
}

static bool host_ok(bst_str h)
{
	if (h.len == 0 || h.len > 253)
		return false;
	for (uint32_t i = 0; i < h.len; i++) {
		char c = h.p[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
		      c == '.'))
			return false;
	}
	return true;
}

/* 308 to https on the same host (a name of the server: the Host header when it matched one,
 * else the first name) and the same target. */
static void redirect(bst_stream *s)
{
	bst_str host = { NULL, 0 };
	if (s->host_matched) {
		const bst_header *h = bst_headers_get_name(&s->req.head.headers, BST_S("host"));
		bst_str v = h != NULL ? h->value : s->req.head.authority;
		const char *colon = v.p != NULL ? memchr(v.p, ':', v.len) : NULL;
		if (colon != NULL)
			v.len = (uint32_t)(colon - v.p);
		if (host_ok(v))
			host = v;
	}
	if (host.len == 0 && s->server->nnames > 0)
		host = (bst_str){ s->server->names[0], (uint32_t)strlen(s->server->names[0]) };
	bst_str target = s->req.head.form == BST_TARGET_ORIGIN ? s->req.head.target : BST_S("/");
	if (host.len == 0 || !host_ok(host)) {
		(void)bst_send_error(s, 400);
		return;
	}
	size_t n = 8 + host.len + target.len;
	char *loc = bst_arena_alloc(s->arena, n);
	if (loc == NULL) {
		s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
		return;
	}
	memcpy(loc, "https://", 8);
	memcpy(loc + 8, host.p, host.len);
	memcpy(loc + 8 + host.len, target.p, target.len);
	(void)bst_send_error_hdr(s, 308, BST_S("Location"), (bst_str){ loc, (uint32_t)n });
}

bool bst_acme_http01_serve(bst_stream *s)
{
	if (s->server == NULL || !s->server->tls_auto)
		return false;
	size_t pl = sizeof PREFIX - 1;
	if (s->uri.len > pl && memcmp(s->uri.p, PREFIX, pl) == 0 && bst_acme_region_ != NULL) {
		bst_str token = { s->uri.p + pl, (uint32_t)(s->uri.len - pl) };
		char ka[BST_ACME_KEYAUTH_MAX];
		int n = bst_acme_http01_get(token, ka, sizeof ka);
		if (n < 0) {
			(void)bst_send_error(s, 404);
			return true;
		}
		if (s->req.head.method != BST_M_GET && s->req.head.method != BST_M_HEAD) {
			(void)bst_send_error_hdr(s, 405, BST_S("Allow"), BST_S("GET, HEAD"));
			return true;
		}
		if (send_text(s, 200, ka, (size_t)n) != 0)
			s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
		return true;
	}
	if (s->server->acme_redirect && !bst_stream_is_tls(s)) {
		redirect(s);
		return true;
	}
	return false;
}

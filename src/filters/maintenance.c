/* Maintenance mode: every request in the scope gets a 503 with Retry-After, except those from
 * maintenance_allow peers. The page is the configured file (read at load) or the default error
 * page. Runs in the router before any handler, so nothing reaches files or upstreams. */
#include "filters/extras.h"

#include "core/buf.h"
#include "ops/admin.h"
#include "proxy/handler.h"

#include <stdio.h>
#include <string.h>

static int send_page(bst_stream *s, const bst_cfg_extras *x, bst_str ra)
{
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = 503;
	h.content_length = (int64_t)x->maintenance_len;
	bst_headers_init(&h.headers, s->arena);
	if (bst_headers_add(&h.headers, BST_S("Retry-After"), ra) != 0 ||
	    bst_headers_add(&h.headers, BST_S("Content-Type"), BST_S("text/html; charset=utf-8")) != 0 ||
	    bst_headers_add(&h.headers, BST_S("Cache-Control"), BST_S("no-store")) != 0)
		return -1;
	bool head = s->req.head.method == BST_M_HEAD || x->maintenance_len == 0;
	if (bst_stream_send_head(s, &h, head) != 0)
		return -1;
	if (head)
		return 0;
	bst_buf *b = bst_buf_new(x->maintenance_len);
	if (b == NULL)
		return -1;
	memcpy(b->data, x->maintenance_body, x->maintenance_len);
	b->len = x->maintenance_len;
	bst_chain c;
	bst_chain_init(&c, s->chain_slab);
	int rc = bst_chain_add_mem(&c, b, 0, b->len);
	bst_buf_unref(b);
	if (rc != 0)
		return -1;
	return bst_stream_send_body(s, &c, true, NULL, NULL);
}

bool bst_maintenance_check(bst_stream *s)
{
	const bst_cfg_extras *x = &s->cfg->extras;
	if (!x->maintenance && !bst_admin_maintenance(s->server)) /* or forced by the admin API */
		return false;
	if (s->has_peer && bst_proxy_cidr_match(&x->maintenance_allow, &s->peer.ip))
		return false;
	char ra[16];
	int n = snprintf(ra, sizeof ra, "%u", x->maintenance_retry_after);
	char *v = bst_arena_alloc(s->arena, (size_t)n);
	if (v == NULL) {
		s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
		return true;
	}
	memcpy(v, ra, (size_t)n);
	bst_str rav = { v, (uint32_t)n };
	if (x->maintenance_body != NULL) {
		if (send_page(s, x, rav) != 0)
			s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
	} else {
		(void)bst_send_error_hdr(s, 503, BST_S("Retry-After"), rav);
	}
	return true;
}

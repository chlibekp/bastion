#include "filters/headers.h"

#include "core/log.h"
#include "route/vars.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* The statuses `expires` marks cacheable, as nginx does. */
static bool expires_status(int st)
{
	return st == 200 || st == 201 || st == 204 || st == 206 || st == 301 || st == 302 ||
	       st == 303 || st == 304 || st == 307 || st == 308;
}

static void apply_expires(bst_stream *s, bst_resp_head *h)
{
	const bst_cfg_expires *x = &s->cfg->expires;
	if (!x->set || !expires_status(h->status))
		return;
	char cc[64];
	int n;
	if (x->secs == 0)
		n = snprintf(cc, sizeof cc, "no-cache");
	else
		n = snprintf(cc, sizeof cc, "max-age=%llu%s", (unsigned long long)x->secs,
			     x->immutable ? ", immutable" : "");
	char *v = bst_arena_alloc(s->arena, (size_t)n + 1);
	char *e = bst_arena_alloc(s->arena, BST_HTTP_DATE_LEN + 1);
	if (v == NULL || e == NULL)
		return;
	memcpy(v, cc, (size_t)n + 1);
	time_t at = x->secs == 0 ? 0 : time(NULL) + (time_t)(x->secs > 315360000u ? 315360000u : x->secs);
	if (bst_http_date_format(at, e) != BST_HTTP_DATE_LEN)
		return;
	(void)bst_headers_set(&h->headers, BST_S("Cache-Control"), (bst_str){ v, (uint32_t)n });
	(void)bst_headers_set(&h->headers, BST_S("Expires"), (bst_str){ e, BST_HTTP_DATE_LEN });
}

void bst_filter_response_headers(bst_stream *s, bst_resp_head *h)
{
	const bst_cfg_list *ops = &s->cfg->resp_hdr_ops;
	bool ok_status = h->status >= 200 && h->status < 400;
	for (size_t i = 0; i < ops->n; i++) {
		const bst_cfg_hdr_op *op = ops->items[i];
		bst_str name = { op->name, op->name_len };
		if (op->kind == BST_HDR_REMOVE) {
			(void)bst_headers_remove_name(&h->headers, name);
			continue;
		}
		if (!ok_status && !op->always)
			continue;
		bst_var_ctx ctx;
		bst_var_ctx_init(&ctx, s);
		ctx.status = h->status;
		bst_str v;
		int rc = bst_header_tpl_eval(op->value, &ctx, s->arena, &v);
		if (rc == BST_TPL_UNSAFE) { /* a value from the request carried a line break: never sent */
			bst_log(BST_LOG_WARN, "header %s dropped: its value holds a line break (%s)",
				op->name, "possible header injection");
			continue;
		}
		if (rc != BST_TPL_OK) {
			bst_log(BST_LOG_WARN, "header %s dropped: out of memory", op->name);
			continue;
		}
		int arc = op->kind == BST_HDR_ADD ? bst_headers_add(&h->headers, name, v)
						  : bst_headers_set(&h->headers, name, v);
		if (arc != 0)
			bst_log(BST_LOG_WARN, "header %s dropped: out of memory", op->name);
	}
	apply_expires(s, h);
}

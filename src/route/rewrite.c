#include "route/rewrite.h"

#include "core/log.h"
#include "route/uri.h"
#include "route/vars.h"

#include <string.h>

int bst_rewrite_run(bst_stream *s, const bst_cfg_list *rules, bst_rewrite_flag *flag)
{
	*flag = BST_REWRITE_NONE;
	for (size_t i = 0; i < rules->n; i++) {
		const bst_cfg_rewrite *r = rules->items[i];
		bst_captures caps;
		int rc = bst_regex_match(r->re, s->uri, &caps);
		if (rc == BST_RE_NOMATCH)
			continue;
		if (rc == BST_RE_LIMIT) {
			bst_log(BST_LOG_WARN, "rewrite: regex limit reached on a %u-byte path: 500",
				(unsigned)s->uri.len);
			return 500;
		}
		bst_var_ctx ctx;
		bst_var_ctx_init(&ctx, s);
		ctx.caps = &caps; /* $1..$9 are the rewrite's own groups */
		bst_str out = bst_tpl_eval(r->repl, &ctx, s->arena);
		if (bst_str_failed(out))
			return 500;
		const char *q = memchr(out.p, '?', out.len);
		bst_str path = q != NULL ? (bst_str){ out.p, (uint32_t)(q - out.p) } : out;
		char *buf = bst_arena_alloc(s->arena, (size_t)path.len + 1);
		size_t n = 0;
		if (buf == NULL)
			return 500;
		if (bst_uri_clean(path, buf, (size_t)path.len + 1,
				  s->server->common.merge_slashes ? BST_URI_MERGE_SLASHES : 0, &n) != BST_URI_OK) {
			bst_log(BST_LOG_WARN, "rewrite: \"%s\" produced a path that is not absolute: 500",
				r->pattern);
			return 500;
		}
		s->uri = (bst_str){ buf, (uint32_t)n };
		s->uri_changed = true;
		if (q != NULL) { /* a '?' in the replacement replaces the arguments, even with none */
			s->req.head.query = (bst_str){ q + 1, (uint32_t)(out.len - path.len - 1) };
			s->req.head.has_query = out.len - path.len - 1 > 0;
		}
		if (r->flag != BST_REWRITE_NONE) {
			*flag = r->flag;
			return 0;
		}
	}
	return 0;
}

/* ---- request header operations ---- */

void bst_apply_request_headers(bst_stream *s)
{
	const bst_cfg_list *ops = &s->cfg->req_hdr_ops;
	for (size_t i = 0; i < ops->n; i++) {
		const bst_cfg_hdr_op *op = ops->items[i];
		bst_str name = { op->name, op->name_len };
		if (op->kind == BST_HDR_REMOVE) {
			(void)bst_headers_remove_name(&s->req.head.headers, name);
			continue;
		}
		bst_var_ctx ctx;
		bst_var_ctx_init(&ctx, s);
		bst_str v;
		int rc = bst_header_tpl_eval(op->value, &ctx, s->arena, &v);
		if (rc == BST_TPL_UNSAFE) {
			bst_log(BST_LOG_WARN, "request_header_set %s: the value holds a line break: dropped",
				op->name);
			continue;
		}
		if (rc != BST_TPL_OK || bst_headers_set(&s->req.head.headers, name, v) != 0)
			bst_log(BST_LOG_WARN, "request_header_set %s: out of memory", op->name);
	}
}

/* security_headers basic|strict and the per-header overrides, plus the request ID echo: added
 * to every final response head. A header the handler (or the upstream) already set is kept
 * unless its override says force, so an application's own CSP is not clobbered. HSTS is only
 * ever sent over TLS (RFC 6797 section 7.2). */
#include "filters/extras.h"

#include <string.h>

typedef struct sec_def {
	const char *name;
	const char *basic;  /* NULL: not in the preset */
	const char *strict;
} sec_def;

static const sec_def defs[BST_SEC_COUNT_] = {
	[BST_SEC_HSTS] = { "Strict-Transport-Security", "max-age=31536000",
			   "max-age=63072000; includeSubDomains" },
	[BST_SEC_CSP] = { "Content-Security-Policy", NULL,
			  "default-src 'self'; frame-ancestors 'none'; base-uri 'self'" },
	[BST_SEC_FRAME_OPTIONS] = { "X-Frame-Options", "SAMEORIGIN", "DENY" },
	[BST_SEC_REFERRER_POLICY] = { "Referrer-Policy", "strict-origin-when-cross-origin",
				      "no-referrer" },
	[BST_SEC_PERMISSIONS_POLICY] = { "Permissions-Policy", NULL,
					 "camera=(), microphone=(), geolocation=()" },
	[BST_SEC_CONTENT_TYPE_OPTIONS] = { "X-Content-Type-Options", "nosniff", "nosniff" },
};

static void security(bst_stream *s, bst_resp_head *h)
{
	const bst_cfg_extras *x = &s->cfg->extras;
	bool tls = bst_stream_is_tls(s);
	for (int i = 0; i < BST_SEC_COUNT_; i++) {
		const sec_def *d = &defs[i];
		const char *v = x->security == BST_SEC_STRICT  ? d->strict
				: x->security == BST_SEC_BASIC ? d->basic
							       : NULL;
		if (x->sec_value[i] != NULL)
			v = x->sec_value[i]; /* the override, also without a preset */
		if (v == NULL || v[0] == '\0')
			continue;
		if (i == BST_SEC_HSTS && !tls)
			continue;
		bst_str name = { d->name, (uint32_t)strlen(d->name) };
		bst_str val = { v, (uint32_t)strlen(v) };
		if (bst_headers_get_name(&h->headers, name) != NULL) {
			if (!x->sec_force[i])
				continue; /* the handler's own value wins */
			(void)bst_headers_set(&h->headers, name, val);
			continue;
		}
		(void)bst_headers_add(&h->headers, name, val);
	}
}

void bst_extras_response_head(bst_stream *s, bst_resp_head *h)
{
	const bst_cfg_extras *x = &s->cfg->extras;
	if (x->request_id && s->request_id.p != NULL && x->request_id_header != NULL) {
		bst_str name = { x->request_id_header, (uint32_t)strlen(x->request_id_header) };
		(void)bst_headers_set(&h->headers, name, s->request_id);
	}
	if (x->security != BST_SEC_OFF)
		security(s, h);
	else
		for (int i = 0; i < BST_SEC_COUNT_; i++)
			if (x->sec_value[i] != NULL) {
				security(s, h); /* overrides alone */
				break;
			}
}

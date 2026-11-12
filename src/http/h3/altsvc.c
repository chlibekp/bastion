/* Alt-Svc advertisement of a server's HTTP/3 listener (altsvc.h) and its directive. */
#include "http/h3/altsvc.h"

#include "config/schema.h"

#include <stdio.h>
#include <string.h>

bst_str bst_alt_svc(const bst_cfg_server *srv, char *buf)
{
	const char *v = srv->common.http.alt_svc;
	if (v != NULL)
		return (bst_str){ v, (uint32_t)strlen(v) }; /* "" for off */
	for (size_t i = 0; i < srv->nlistens; i++) {
		if (!srv->listens[i].http3)
			continue;
		int n = snprintf(buf, BST_ALT_SVC_MAX, "h3=\":%u\"; ma=86400", (unsigned)srv->listens[i].addr.port);
		return n > 0 && n < BST_ALT_SVC_MAX ? (bst_str){ buf, (uint32_t)n } : BST_S("");
	}
	return BST_S("");
}

static int ap_alt_svc(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (strcmp(a->text, "auto") == 0) {
		c->common->http.alt_svc = NULL;
		return 0;
	}
	if (strcmp(a->text, "off") == 0) {
		c->common->http.alt_svc = "";
		return 0;
	}
	if (a->len >= BST_ALT_SVC_MAX) {
		bst_err_set(e, "alt_svc: the value is longer than %d bytes", BST_ALT_SVC_MAX - 1);
		return -1;
	}
	c->common->http.alt_svc = bst_cfg_strdup(c, a->text, a->len, e);
	return c->common->http.alt_svc != NULL ? 0 : -1;
}

static const bst_directive altsvc_dirs[] = {
	{ .name = "alt_svc", .contexts = BST_CTX_SERVER, .apply = ap_alt_svc, .default_value = "auto",
	  .doc = "The Alt-Svc field (RFC 7838) of the server's HTTP/1.1 and HTTP/2 responses, which "
		 "tells clients where the same server speaks HTTP/3. auto: `h3=\":<port>\"; ma=86400` "
		 "for the server's first `listen ... http3`, nothing when it has none. off: no field. "
		 "Any other value is sent as written. A handler that sets Alt-Svc keeps its own; "
		 "HTTP/3 responses carry none.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } } },
};
BST_DIRECTIVES(altsvc_dirs);

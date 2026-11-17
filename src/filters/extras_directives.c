/* The directives of the small HTTP features (Phase 11, Task 3): Early Hints, request IDs,
 * security header presets, maintenance mode and the upstream response size limit. Every one
 * inherits from global to server to location. */
#include "config/compile.h"
#include "config/values.h"
#include "core/cidr.h"
#include "core/str.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define UP1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }
#define ANY_ARGS(...) .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { __VA_ARGS__ } }
#define GSL (BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION)
#define SEC 1000000
#define MAINT_MAX (1u << 20) /* the largest maintenance page */

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static bool arg_bool(const bst_directive *d, const bst_ast_node *n)
{
	bool v = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	return v;
}

static int ap_early_hints(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->extras.early_hints = arg_bool(d, n);
	return 0;
}

static int ap_early_hint(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	char *v = bst_cfg_strdup(c, a->text, a->len, e);
	if (v == NULL)
		return -1;
	return bst_cfg_list_append(c, &c->common->extras.early_links, v, e);
}

static int ap_request_id(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	c->common->extras.request_id = arg_bool(d, n);
	return 0;
}

static int ap_request_id_header(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n,
				bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	for (size_t i = 0; i < a->len; i++) {
		char ch = a->text[i];
		if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
		      ch == '-' || ch == '_')) {
			bst_err_set(e, "request_id_header: '%.*s' is not a header name", (int)a->len, a->text);
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
	}
	char *v = bst_cfg_strdup(c, a->text, a->len, e);
	if (v == NULL)
		return -1;
	c->common->extras.request_id_header = v;
	return 0;
}

static int cidr_list(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e,
		     bst_cfg_list *l)
{
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		bst_cidr *x = bst_arena_alloc(c->arena, sizeof *x);
		if (x == NULL) {
			bst_err_set(e, "out of memory");
			return -1;
		}
		if (!bst_cidr_parse(as_str(bst_dir_pos(d, n, i)), x))
			return 0; /* validated by the argspec */
		if (bst_cfg_list_append(c, l, x, e) != 0)
			return -1;
	}
	return 0;
}

static int ap_rid_trust(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return cidr_list(c, d, n, e, &c->common->extras.request_id_trust);
}

static int ap_security(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bst_str v = as_str(bst_dir_pos(d, n, 0));
	c->common->extras.security = bst_str_eq(v, BST_S("strict")) ? BST_SEC_STRICT
				     : bst_str_eq(v, BST_S("basic")) ? BST_SEC_BASIC
								       : BST_SEC_OFF;
	return 0;
}

/* hsts, csp, ...: <value>|off [force] */
static int sec_override(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e,
			bst_sec_hdr which)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bool off = bst_str_eq(as_str(a), BST_S("off"));
	char *v = off ? bst_cfg_strdup(c, "", 0, e) : bst_cfg_strdup(c, a->text, a->len, e);
	if (v == NULL)
		return -1;
	if (memchr(v, '\r', strlen(v)) != NULL || memchr(v, '\n', strlen(v)) != NULL) {
		bst_err_set(e, "%s: a header value can not hold a line break", d->name);
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	c->common->extras.sec_value[which] = v;
	c->common->extras.sec_force[which] = bst_dir_npos(d, n) > 1;
	return 0;
}

#define AP_SEC(fn, which)                                                                    \
	static int fn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e) \
	{                                                                                    \
		return sec_override(c, d, n, e, which);                                      \
	}

AP_SEC(ap_hsts, BST_SEC_HSTS)
AP_SEC(ap_csp, BST_SEC_CSP)
AP_SEC(ap_frame_options, BST_SEC_FRAME_OPTIONS)
AP_SEC(ap_referrer_policy, BST_SEC_REFERRER_POLICY)
AP_SEC(ap_permissions_policy, BST_SEC_PERMISSIONS_POLICY)
AP_SEC(ap_cto, BST_SEC_CONTENT_TYPE_OPTIONS)

/* maintenance on|off|<file>: the file is read once, here, at load. */
static int ap_maintenance(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_str v = as_str(a);
	bst_cfg_extras *x = &c->common->extras;
	x->maintenance_body = NULL;
	x->maintenance_len = 0;
	if (bst_str_eq(v, BST_S("off"))) {
		x->maintenance = false;
		return 0;
	}
	x->maintenance = true;
	if (bst_str_eq(v, BST_S("on")))
		return 0;
	char *path = bst_cfg_strdup(c, a->text, a->len, e);
	if (path == NULL)
		return -1;
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	struct stat st;
	if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > (off_t)MAINT_MAX) {
		int err = fd < 0 ? errno : EINVAL;
		if (fd >= 0)
			close(fd);
		bst_err_set(e, "maintenance: can not use '%s' as the page (%s; a regular file up to 1 MiB)",
			    path, strerror(err));
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	char *body = bst_arena_alloc(c->arena, (size_t)st.st_size + 1);
	size_t got = 0;
	while (body != NULL && got < (size_t)st.st_size) {
		ssize_t r = read(fd, body + got, (size_t)st.st_size - got);
		if (r <= 0)
			break;
		got += (size_t)r;
	}
	close(fd);
	if (body == NULL || got != (size_t)st.st_size) {
		bst_err_set(e, "maintenance: reading '%s' failed", path);
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	x->maintenance_body = body;
	x->maintenance_len = got;
	return 0;
}

static int ap_maint_allow(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	return cidr_list(c, d, n, e, &c->common->extras.maintenance_allow);
}

static int ap_maint_retry(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint64_t us = 0;
	(void)bst_parse_duration_us(as_str(bst_dir_pos(d, n, 0)), &us);
	c->common->extras.maintenance_retry_after = (unsigned)(us / SEC);
	return 0;
}

static int ap_up_max(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint64_t v = 0;
	(void)bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->extras.upstream_max_response_size = v;
	return 0;
}

static const char *const sec_v[] = { "off", "basic", "strict", NULL };
static const char *const force_v[] = { "force", NULL };

#define SEC_DIR(nm, fn, what)                                                               \
	{ .name = nm, .contexts = GSL, .apply = fn,                                          \
	  .doc = "Overrides the " what " of security_headers: a value, or off for none. With " \
		 "force it replaces a value the handler or upstream set; without, theirs is "  \
		 "kept.",                                                                    \
	  .args = { .min_args = 1, .max_args = 2,                                            \
		    .pos = { { .kind = BST_T_STRING }, { .kind = BST_T_ENUM, .enum_values = force_v } } } }

static const bst_directive extras_dirs[] = {
	{ .name = "early_hints", .contexts = GSL, .apply = ap_early_hints, .default_value = "off",
	  .doc = "on: a 103 Early Hints response with the early_hint Link values is sent before the "
		 "handler starts, over HTTP/1.1, HTTP/2 and HTTP/3 (never to an HTTP/1.0 client). A "
		 "103 from a proxied upstream is forwarded either way.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "early_hint", .contexts = GSL, .apply = ap_early_hint, .repeatable = true,
	  .doc = "A Link value for the 103 Early Hints response, e.g. \"</app.css>; rel=preload; "
		 "as=style\". Repeat it for several.",
	  UP1({ .kind = BST_T_STRING }) },
	{ .name = "request_id", .contexts = GSL, .apply = ap_request_id, .default_value = "off",
	  .doc = "on: every request gets a random 128-bit ID ($request_id, 32 hex digits), sent "
		 "upstream and back to the client in request_id_header. An ID the client sent is "
		 "replaced unless the peer is in request_id_trust.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "request_id_header", .contexts = GSL, .apply = ap_request_id_header,
	  .default_value = "X-Request-ID",
	  .doc = "The header field that carries the request ID.",
	  UP1({ .kind = BST_T_STRING }) },
	{ .name = "request_id_trust", .contexts = GSL, .apply = ap_rid_trust,
	  .doc = "Peers (CIDR) whose incoming request ID is kept (a balancer that already made "
		 "one). A kept ID is 1 to 128 letters, digits, '-', '_' or '.', else it is replaced.",
	  ANY_ARGS({ .kind = BST_T_CIDR }) },
	{ .name = "security_headers", .contexts = GSL, .apply = ap_security, .default_value = "off",
	  .doc = "Adds a set of security headers to every response. basic: X-Content-Type-Options: "
		 "nosniff, X-Frame-Options: SAMEORIGIN, Referrer-Policy: "
		 "strict-origin-when-cross-origin, and over TLS Strict-Transport-Security: "
		 "max-age=31536000. strict: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, "
		 "Referrer-Policy: no-referrer, Content-Security-Policy: default-src 'self'; "
		 "frame-ancestors 'none'; base-uri 'self', Permissions-Policy: camera=(), "
		 "microphone=(), geolocation=(), and over TLS Strict-Transport-Security: "
		 "max-age=63072000; includeSubDomains. HSTS is never sent over cleartext. A header "
		 "the handler or upstream already set is kept, unless its override says force.",
	  UP1({ .kind = BST_T_ENUM, .enum_values = sec_v }) },
	SEC_DIR("hsts", ap_hsts, "Strict-Transport-Security (TLS only)"),
	SEC_DIR("csp", ap_csp, "Content-Security-Policy"),
	SEC_DIR("frame_options", ap_frame_options, "X-Frame-Options"),
	SEC_DIR("referrer_policy", ap_referrer_policy, "Referrer-Policy"),
	SEC_DIR("permissions_policy", ap_permissions_policy, "Permissions-Policy"),
	SEC_DIR("content_type_options", ap_cto, "X-Content-Type-Options"),
	{ .name = "maintenance", .contexts = GSL, .apply = ap_maintenance, .default_value = "off",
	  .doc = "on: every request is answered 503 with Retry-After, except from "
		 "maintenance_allow peers. A file path instead of on: that file (read at load, up to "
		 "1 MiB) is the HTML page sent. A runtime toggle comes with the admin API.",
	  UP1({ .kind = BST_T_STRING }) },
	{ .name = "maintenance_allow", .contexts = GSL, .apply = ap_maint_allow,
	  .doc = "Peers (CIDR) served as usual during maintenance.",
	  ANY_ARGS({ .kind = BST_T_CIDR }) },
	{ .name = "maintenance_retry_after", .contexts = GSL, .apply = ap_maint_retry,
	  .default_value = "300s",
	  .doc = "The Retry-After of the maintenance 503, in whole seconds.",
	  UP1({ .kind = BST_T_DURATION, .min = SEC, .max = 86400ll * SEC }) },
	{ .name = "upstream_max_response_size", .contexts = GSL, .apply = ap_up_max,
	  .default_value = "0",
	  .doc = "The largest response body accepted from an upstream; 0 means unlimited. A larger "
		 "declared Content-Length is a 502; a body that grows past it once the response "
		 "began aborts the client's stream (never a clean end of a cut response).",
	  UP1({ .kind = BST_T_SIZE, .min = 0 }) },
};
BST_DIRECTIVES(extras_dirs);

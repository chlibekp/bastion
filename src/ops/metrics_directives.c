/* The `metrics {}` block (ops/metrics.h): listen, path, allow, auth_basic, per_location. */
#include "config/compile.h"
#include "config/values.h"
#include "core/str.h"
#include "ops/metrics.h"

#include <stdlib.h>
#include <string.h>

#define MC BST_CTX_METRICS

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static bst_cfg_metrics *M(bst_cfg_ctx *c)
{
	return c->global->metrics;
}

static int ap_metrics(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)d, (void)n;
	bst_cfg_metrics *m = bst_arena_alloc(c->arena, sizeof *m);
	if (m == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	memset(m, 0, sizeof *m);
	m->listen.port = BST_METRICS_DEFAULT_PORT;
	m->listen.ip.family = BST_IP_V4;
	m->listen.ip.b[0] = 127;
	m->listen.ip.b[3] = 1;
	m->path = "/metrics";
	c->global->metrics = m;
	return 0;
}

static bool loopback(const bst_ip *ip)
{
	if (ip->family == BST_IP_V4)
		return ip->b[0] == 127;
	static const uint8_t one[16] = { [15] = 1 };
	return memcmp(ip->b, one, 16) == 0;
}

/* "addr:port" or "[v6]:port". */
static bool parse_hostport(bst_str s, bst_sockaddr *out)
{
	const char *p = s.p, *end = s.p + s.len;
	bst_str host;
	const char *colon;
	if (s.len > 0 && p[0] == '[') {
		const char *rb = memchr(p, ']', s.len);
		if (rb == NULL || rb + 1 >= end || rb[1] != ':')
			return false;
		host = (bst_str){ p + 1, (uint32_t)(rb - p - 1) };
		colon = rb + 1;
	} else {
		colon = memrchr(p, ':', s.len);
		if (colon == NULL || memchr(p, ':', (size_t)(colon - p)) != NULL)
			return false; /* a bare IPv6 address needs brackets */
		host = (bst_str){ p, (uint32_t)(colon - p) };
	}
	const char *q = colon + 1;
	if (q >= end || end - q > 5)
		return false;
	unsigned long port = 0;
	for (; q < end; q++) {
		if (*q < '0' || *q > '9')
			return false;
		port = port * 10 + (unsigned long)(*q - '0');
	}
	if (port == 0 || port > 65535 || !bst_addr_parse(host, &out->ip))
		return false;
	out->port = (uint16_t)port;
	return true;
}

static int ap_listen(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	bst_sockaddr sa;
	if (!parse_hostport(as_str(a), &sa)) {
		bst_err_set(e, "metrics listen: expected address:port or [address]:port");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	if (!loopback(&sa.ip))
		bst_cfg_warn(c, n, "metrics listen %.*s is not a loopback address: metrics are exposed "
				   "to the network (restrict them with allow or auth_basic)",
			     (int)a->len, a->text);
	M(c)->listen = sa;
	return 0;
}

static int ap_path(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (a->len == 0 || a->text[0] != '/' || a->len > 128 || memchr(a->text, '?', a->len) != NULL) {
		bst_err_set(e, "metrics path: an absolute path of at most 128 bytes, without a query");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	M(c)->path = bst_cfg_strdup(c, a->text, a->len, e);
	return M(c)->path == NULL ? -1 : 0;
}

static int ap_allow(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_metrics *m = M(c);
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		bst_cidr x;
		if (!bst_cidr_parse(as_str(a), &x)) {
			bst_ip ip;
			if (!bst_addr_parse(as_str(a), &ip)) {
				bst_err_set(e, "metrics allow: not an address or CIDR");
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
			x.ip = ip;
			x.prefix = ip.family == BST_IP_V4 ? 32 : 128;
		}
		if (m->nallow == BST_METRICS_ALLOW_MAX) {
			bst_err_set(e, "metrics allow: at most %d entries", BST_METRICS_ALLOW_MAX);
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		m->allow[m->nallow++] = x;
	}
	return 0;
}

static int ap_auth(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	M(c)->auth_file = bst_cfg_strdup(c, a->text, a->len, e);
	return M(c)->auth_file == NULL ? -1 : 0;
}

static int ap_per_location(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &M(c)->per_location); /* validated */
	return 0;
}

static const bst_directive metrics_dirs[] = {
	{ .name = "metrics", .contexts = BST_CTX_GLOBAL, .apply = ap_metrics, .child_ctx = MC,
	  .doc = "Prometheus metrics, off without this block. The helper process serves the text "
		 "exposition format on a listener of its own (never on a `server` listener), summed "
		 "from per-process counters in shared memory that survive reload, upgrade and worker "
		 "crashes. Label values come from the configuration only: requests whose Host matches "
		 "no server name count under server=\"_other\".",
	  .args = { .block = BST_BLOCK_REQUIRED } },
	{ .name = "listen", .contexts = MC, .apply = ap_listen, .default_value = "127.0.0.1:9145",
	  .doc = "address:port (or [address]:port) the helper serves metrics on. A non-loopback "
		 "address draws a warning at load: protect it with allow or auth_basic.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "path", .contexts = MC, .apply = ap_path, .default_value = "/metrics",
	  .doc = "The path of the scrape; any other path gets 404.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "allow", .contexts = MC, .apply = ap_allow, .repeatable = true,
	  .doc = "Addresses or CIDRs that may scrape (up to 64); others get 403. Without allow, "
		 "every peer that reaches the listener may.",
	  .args = { .min_args = 1, .max_args = BST_METRICS_ALLOW_MAX, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "auth_basic", .contexts = MC, .apply = ap_auth,
	  .doc = "Requires HTTP Basic authentication against this file of `user:$argon2id$...` "
		 "lines (as `bastion passwd` prints them), read by master at load. A scrape without "
		 "valid credentials gets 401.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_PATH } } } },
	{ .name = "per_location", .contexts = MC, .apply = ap_per_location, .default_value = "off",
	  .doc = "on: also count requests per location, bastion_http_location_requests_total "
		 "{server, location}, the location labelled by its pattern.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_BOOL } } } },
};
BST_DIRECTIVES(metrics_dirs);

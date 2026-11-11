#include "route/vars.h"

#include "core/addr.h"
#include "route/uri.h"
#include "tls/conn.h"

#include <stdio.h>
#include <string.h>
#include <sys/random.h>

#define S(c) ((c)->s)
#define NONE ((bst_str){ "", 0 })

static bst_str dup_str(const bst_var_ctx *c, const char *p, size_t n)
{
	char *b = bst_arena_alloc(S(c)->arena, n + 1);
	if (b == NULL)
		return (bst_str){ NULL, 0 };
	memcpy(b, p, n);
	b[n] = '\0';
	return (bst_str){ b, (uint32_t)n };
}

static bst_str num_str(const bst_var_ctx *c, unsigned long v)
{
	char t[24];
	int n = snprintf(t, sizeof t, "%lu", v);
	return dup_str(c, t, (size_t)n);
}

static bst_str var_host(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	bst_str h = S(c)->req.host;
	size_t len = h.len;
	if (len > 0 && h.p[0] == '[') {
		const char *rb = memchr(h.p, ']', len);
		len = rb != NULL ? (size_t)(rb - h.p) + 1 : len;
	} else {
		const char *colon = memchr(h.p, ':', len);
		len = colon != NULL ? (size_t)(colon - h.p) : len;
	}
	char *b = bst_arena_alloc(S(c)->arena, len + 1);
	if (b == NULL)
		return (bst_str){ NULL, 0 };
	for (size_t i = 0; i < len; i++)
		b[i] = h.p[i] >= 'A' && h.p[i] <= 'Z' ? (char)(h.p[i] + 32) : h.p[i];
	b[len] = '\0';
	return (bst_str){ b, (uint32_t)len };
}

static bst_str var_uri(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return S(c)->uri.p != NULL ? S(c)->uri : NONE;
}

static bst_str var_request_uri(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	const bst_req_head *h = &S(c)->req.head;
	if (h->form == BST_TARGET_ORIGIN)
		return h->target;
	size_t n = (size_t)h->path.len + (h->has_query ? (size_t)h->query.len + 1 : 0);
	char *b = bst_arena_alloc(S(c)->arena, n + 1);
	if (b == NULL)
		return (bst_str){ NULL, 0 };
	memcpy(b, h->path.p, h->path.len);
	if (h->has_query) {
		b[h->path.len] = '?';
		memcpy(b + h->path.len + 1, h->query.p, h->query.len);
	}
	b[n] = '\0';
	return (bst_str){ b, (uint32_t)n };
}

static bst_str var_args(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	const bst_req_head *h = &S(c)->req.head;
	return h->has_query ? h->query : NONE;
}

static bst_str var_arg(const bst_var_ctx *c, bst_str name)
{
	bst_str v;
	const bst_req_head *h = &S(c)->req.head;
	if (h->has_query && bst_query_get(h->query, name, &v))
		return v.p != NULL ? v : NONE;
	return NONE;
}

#define HDR_NAME_MAX 128

static bst_str var_http(const bst_var_ctx *c, bst_str sfx)
{
	if (sfx.len == 0 || sfx.len > HDR_NAME_MAX)
		return NONE;
	char name[HDR_NAME_MAX];
	for (uint32_t i = 0; i < sfx.len; i++)
		name[i] = sfx.p[i] == '_' ? '-' : sfx.p[i];
	const bst_header *h = bst_headers_get_name(&S(c)->req.head.headers,
						    (bst_str){ name, sfx.len });
	return h != NULL ? h->value : NONE;
}

static bst_str var_cookie(const bst_var_ctx *c, bst_str name)
{
	const bst_header *h = NULL;
	while ((h = bst_headers_next(&S(c)->req.head.headers, h, BST_H_COOKIE)) != NULL) {
		const char *p = h->value.p, *end = p + h->value.len;
		while (p < end) {
			while (p < end && (*p == ' ' || *p == ';' || *p == '\t'))
				p++;
			const char *k = p;
			while (p < end && *p != '=' && *p != ';')
				p++;
			size_t klen = (size_t)(p - k);
			const char *v = p < end && *p == '=' ? p + 1 : p;
			const char *ve = v;
			while (ve < end && *ve != ';')
				ve++;
			if (klen == name.len && memcmp(k, name.p, klen) == 0) {
				size_t vl = (size_t)(ve - v);
				while (vl > 0 && (v[vl - 1] == ' ' || v[vl - 1] == '\t'))
					vl--;
				return (bst_str){ v, (uint32_t)vl };
			}
			p = ve;
		}
	}
	return NONE;
}

static bst_str var_remote_addr(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	if (!S(c)->has_peer)
		return NONE;
	char t[BST_ADDR_STRLEN];
	bst_ip ip = bst_ip_canon(&S(c)->peer.ip);
	size_t n = bst_addr_format(&ip, t, sizeof t);
	return n > 0 ? dup_str(c, t, n) : NONE;
}

static bst_str var_remote_port(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return S(c)->has_peer ? num_str(c, S(c)->peer.port) : NONE;
}

static bst_str var_scheme(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return bst_tls_var(S(c)->transport, "protocol") != NULL ? BST_S("https") : BST_S("http");
}

static bst_str tls_var(const bst_var_ctx *c, const char *name)
{
	const char *v = bst_tls_var(S(c)->transport, name);
	return v != NULL ? (bst_str){ v, (uint32_t)strlen(v) } : NONE;
}

static bst_str var_ssl_protocol(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return tls_var(c, "protocol");
}

static bst_str var_ssl_cipher(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return tls_var(c, "cipher");
}

static bst_str var_ssl_client_verify(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return tls_var(c, "client_verify");
}

static bst_str var_ssl_client_s_dn(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return tls_var(c, "client_s_dn");
}

static bst_str var_ssl_client_san_dns(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return tls_var(c, "client_san_dns");
}

static bst_str var_ssl_client_fingerprint(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return tls_var(c, "client_fingerprint");
}

static bst_str var_ja4(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return tls_var(c, "ja4");
}

static bst_str var_ssl_session_reused(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return tls_var(c, "session_reused");
}

static bst_str var_request_method(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return S(c)->req.head.method_str;
}

static bst_str var_status(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	return c->status > 0 ? num_str(c, (unsigned long)c->status) : NONE;
}

static bst_str var_request_id(const bst_var_ctx *c, bst_str sfx)
{
	(void)sfx;
	bst_stream *s = S(c);
	if (s->request_id.p == NULL) {
		unsigned char r[16];
		static const char hex[] = "0123456789abcdef";
		char *b = bst_arena_alloc(s->arena, 33);
		if (b == NULL || getrandom(r, sizeof r, 0) != (ssize_t)sizeof r)
			return NONE;
		for (size_t i = 0; i < sizeof r; i++) {
			b[2 * i] = hex[r[i] >> 4];
			b[2 * i + 1] = hex[r[i] & 15];
		}
		b[32] = '\0';
		s->request_id = (bst_str){ b, 32 };
	}
	return s->request_id;
}

#define CAPVAR(n)                                                                       \
	static bst_str var_cap##n(const bst_var_ctx *c, bst_str sfx)                    \
	{                                                                               \
		(void)sfx;                                                              \
		return bst_captures_get(c->caps, n);                                    \
	}
CAPVAR(1) CAPVAR(2) CAPVAR(3) CAPVAR(4) CAPVAR(5) CAPVAR(6) CAPVAR(7) CAPVAR(8) CAPVAR(9)

static const bst_var_def req_vars[] = {
	{ "host", var_host, false },
	{ "uri", var_uri, false },
	{ "request_uri", var_request_uri, false },
	{ "args", var_args, false },
	{ "arg_", var_arg, true },
	{ "http_", var_http, true },
	{ "cookie_", var_cookie, true },
	{ "remote_addr", var_remote_addr, false },
	{ "remote_port", var_remote_port, false },
	{ "scheme", var_scheme, false },
	{ "ssl_protocol", var_ssl_protocol, false },
	{ "ssl_cipher", var_ssl_cipher, false },
	{ "ssl_session_reused", var_ssl_session_reused, false },
	{ "ja4", var_ja4, false },
	{ "ssl_client_verify", var_ssl_client_verify, false },
	{ "ssl_client_s_dn", var_ssl_client_s_dn, false },
	{ "ssl_client_san_dns", var_ssl_client_san_dns, false },
	{ "ssl_client_fingerprint", var_ssl_client_fingerprint, false },
	{ "request_method", var_request_method, false },
	{ "status", var_status, false },
	{ "request_id", var_request_id, false },
	{ "1", var_cap1, false }, { "2", var_cap2, false }, { "3", var_cap3, false },
	{ "4", var_cap4, false }, { "5", var_cap5, false }, { "6", var_cap6, false },
	{ "7", var_cap7, false }, { "8", var_cap8, false }, { "9", var_cap9, false },
};
BST_VARS(req_vars);

bool bst_var_is_request_input(bst_var_fn fn)
{
	if (fn == var_arg || fn == var_http || fn == var_cookie || fn == var_args)
		return true;
	return fn == var_cap1 || fn == var_cap2 || fn == var_cap3 || fn == var_cap4 ||
	       fn == var_cap5 || fn == var_cap6 || fn == var_cap7 || fn == var_cap8 ||
	       fn == var_cap9;
}

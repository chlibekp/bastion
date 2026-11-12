/* Which fields cross the proxy, both ways (RFC 9110 section 7.6.1, RFC 7239).
 *
 * Hop-by-hop fields never cross. Neither does a field a peer nominates in Connection, except the
 * ones that carry end-to-end meaning a peer must not be able to strip that way: a client sending
 * `Connection: X-Forwarded-For` or `Connection: Authorization` changes nothing, since forwarding
 * fields are regenerated after this filter and the protected ones are kept. */
#include "core/cidr.h"
#include "proxy/handler.h"
#include "proxy/upstream.h"
#include "tls/conn.h"

#include <stdio.h>
#include <string.h>

static bool is_hop_by_hop(bst_hdr_id id)
{
	switch (id) {
	case BST_H_CONNECTION:
	case BST_H_KEEP_ALIVE:
	case BST_H_PROXY_CONNECTION:
	case BST_H_TE:
	case BST_H_TRAILER:
	case BST_H_TRANSFER_ENCODING:
	case BST_H_UPGRADE:
	case BST_H_CONTENT_LENGTH: /* framing is ours to write */
		return true;
	default:
		return false;
	}
}

/* Fields a Connection header cannot remove. */
static bool is_protected(bst_hdr_id id)
{
	switch (id) {
	case BST_H_AUTHORIZATION:
	case BST_H_COOKIE:
	case BST_H_HOST:
	case BST_H_CONTENT_TYPE:
	case BST_H_CONTENT_ENCODING:
	case BST_H_X_FORWARDED_FOR:
	case BST_H_X_FORWARDED_PROTO:
	case BST_H_X_FORWARDED_HOST:
	case BST_H_FORWARDED:
	case BST_H_X_REAL_IP:
		return true;
	default:
		return false;
	}
}

static bool is_forwarding(bst_hdr_id id)
{
	return id == BST_H_X_FORWARDED_FOR || id == BST_H_X_FORWARDED_PROTO ||
	       id == BST_H_X_FORWARDED_HOST || id == BST_H_FORWARDED || id == BST_H_X_REAL_IP;
}

static bool cidr_contains(const bst_cidr *c, const bst_ip *ip)
{
	bst_ip x = bst_ip_canon(ip);
	if (x.family != c->ip.family)
		return false;
	unsigned full = c->prefix / 8, rest = c->prefix % 8;
	if (memcmp(x.b, c->ip.b, full) != 0)
		return false;
	if (rest == 0)
		return true;
	uint8_t mask = (uint8_t)(0xffu << (8 - rest));
	return (x.b[full] & mask) == (c->ip.b[full] & mask);
}

bool bst_proxy_cidr_match(const bst_cfg_list *list, const bst_ip *ip)
{
	for (size_t i = 0; i < list->n; i++)
		if (cidr_contains(list->items[i], ip))
			return true;
	return false;
}

static bool name_listed(const bst_cfg_list *l, bst_str name)
{
	for (size_t i = 0; i < l->n; i++) {
		const char *n = l->items[i];
		if (bst_str_ieq(name, (bst_str){ n, (uint32_t)strlen(n) }))
			return true;
	}
	return false;
}

/* bst_h1_connection_lists without the dependency on the response parser's header. */
static bool conn_lists(const bst_headers *h, bst_str name)
{
	for (const bst_header *c = bst_headers_next(h, NULL, BST_H_CONNECTION); c != NULL;
	     c = bst_headers_next(h, c, BST_H_CONNECTION)) {
		size_t st = 0;
		for (size_t i = 0; i <= c->value.len; i++) {
			if (i < c->value.len && c->value.p[i] != ',')
				continue;
			bst_str e = { c->value.p + st, (uint32_t)(i - st) };
			while (e.len && (e.p[0] == ' ' || e.p[0] == '\t')) {
				e.p++;
				e.len--;
			}
			while (e.len && (e.p[e.len - 1] == ' ' || e.p[e.len - 1] == '\t'))
				e.len--;
			if (bst_str_ieq(e, name))
				return true;
			st = i + 1;
		}
	}
	return false;
}

/* The joined values of every field called id, ", " between them; empty when none. */
static bst_str joined(const bst_headers *h, bst_hdr_id id, const char *sep, bst_arena *a)
{
	size_t n = 0, sl = strlen(sep), k = 0;
	for (const bst_header *x = bst_headers_next(h, NULL, id); x; x = bst_headers_next(h, x, id))
		n += x->value.len + sl;
	if (n == 0)
		return (bst_str){ "", 0 };
	char *b = bst_arena_alloc(a, n);
	if (b == NULL)
		return (bst_str){ NULL, 0 };
	for (const bst_header *x = bst_headers_next(h, NULL, id); x; x = bst_headers_next(h, x, id)) {
		if (k > 0) {
			memcpy(b + k, sep, sl);
			k += sl;
		}
		memcpy(b + k, x->value.p, x->value.len);
		k += x->value.len;
	}
	return (bst_str){ b, (uint32_t)k };
}

static bst_str cat(bst_arena *a, bst_str x, const char *sep, bst_str y)
{
	size_t sl = strlen(sep);
	char *b = bst_arena_alloc(a, (size_t)x.len + sl + y.len);
	if (b == NULL)
		return (bst_str){ NULL, 0 };
	memcpy(b, x.p, x.len);
	memcpy(b + x.len, sep, sl);
	memcpy(b + x.len + sl, y.p, y.len);
	return (bst_str){ b, (uint32_t)(x.len + sl + y.len) };
}

static bst_str copy_str(bst_arena *a, const char *s, size_t n)
{
	char *b = bst_arena_alloc(a, n ? n : 1);
	if (b == NULL)
		return (bst_str){ NULL, 0 };
	memcpy(b, s, n);
	return (bst_str){ b, (uint32_t)n };
}

int bst_proxy_req_headers(bst_stream *s, bst_headers *out, bst_str *host)
{
	const bst_cfg_proxy *pc = &s->cfg->proxy;
	const bst_headers *in = &s->req.head.headers;
	bst_arena *a = s->arena;
	for (uint32_t i = 0; i < in->n; i++) {
		const bst_header *h = &in->v[i];
		if (is_hop_by_hop(h->id) || h->id == BST_H_HOST || h->id == BST_H_EXPECT ||
		    h->id == BST_H_COOKIE || is_forwarding(h->id))
			continue;
		if (bst_str_ieq(h->name, BST_S("early-data")))
			continue; /* ours to set */
		if (!is_protected(h->id) && conn_lists(in, h->name))
			continue;
		if (bst_headers_add(out, h->name, h->value) != 0)
			return -1;
	}
	/* RFC 9113 section 8.2.3: HTTP/2 (and HTTP/3) may split Cookie; HTTP/1.1 wants one. */
	if (bst_headers_get(in, BST_H_COOKIE) != NULL) {
		bst_str c = joined(in, BST_H_COOKIE, "; ", a);
		if (c.p == NULL || bst_headers_add(out, BST_S("Cookie"), c) != 0)
			return -1;
	}
	if (s->req.early_data && bst_headers_add(out, BST_S("Early-Data"), BST_S("1")) != 0)
		return -1; /* RFC 8470: the upstream may answer 425 */

	/* Host */
	switch (pc->host_mode) {
	case BST_PROXY_HOST_CLIENT:
		*host = s->req.host;
		break;
	case BST_PROXY_HOST_UPSTREAM:
		*host = (bst_str){ pc->up_host, (uint32_t)strlen(pc->up_host) };
		break;
	case BST_PROXY_HOST_VALUE:
		*host = (bst_str){ pc->host_value, (uint32_t)strlen(pc->host_value) };
		break;
	}
	if (host->len == 0)
		*host = (bst_str){ pc->up_host, (uint32_t)strlen(pc->up_host) };

	if (pc->fwd == BST_FWD_OFF)
		return 0;
	char ipbuf[BST_ADDR_STRLEN + 2];
	bst_str ip = { "unknown", 7 };
	bool trusted = false;
	if (s->has_peer) {
		bst_ip canon = bst_ip_canon(&s->peer.ip);
		size_t n = bst_addr_format(&canon, ipbuf, sizeof ipbuf);
		ip = copy_str(a, ipbuf, n);
		trusted = bst_proxy_cidr_match(&pc->trusted, &s->peer.ip);
		if (ip.p == NULL)
			return -1;
	}
	bst_str scheme = bst_tls_var(s->transport, "protocol") != NULL ? BST_S("https") : BST_S("http");
	if (pc->fwd == BST_FWD_XFF) {
		bst_str xff = trusted ? joined(in, BST_H_X_FORWARDED_FOR, ", ", a) : (bst_str){ "", 0 };
		bst_str v = xff.len > 0 ? cat(a, xff, ", ", ip) : ip;
		const bst_header *p = trusted ? bst_headers_get(in, BST_H_X_FORWARDED_PROTO) : NULL;
		const bst_header *hh = trusted ? bst_headers_get(in, BST_H_X_FORWARDED_HOST) : NULL;
		if (v.p == NULL || bst_headers_add(out, BST_S("X-Forwarded-For"), v) != 0 ||
		    bst_headers_add(out, BST_S("X-Forwarded-Proto"), p ? p->value : scheme) != 0 ||
		    (s->req.host.len > 0 &&
		     bst_headers_add(out, BST_S("X-Forwarded-Host"), hh ? hh->value : s->req.host) != 0))
			return -1;
		return 0;
	}
	/* Forwarded: for=, proto=, host= of this hop; earlier hops only from a trusted proxy */
	bool v6 = s->has_peer && bst_ip_canon(&s->peer.ip).family == BST_IP_V6;
	char el[BST_ADDR_STRLEN + 64];
	int n = snprintf(el, sizeof el, "for=%s%.*s%s;proto=%.*s", v6 ? "\"[" : "", (int)ip.len, ip.p,
			 v6 ? "]\"" : "", (int)scheme.len, scheme.p);
	bst_str elem = copy_str(a, el, n > 0 ? (size_t)n : 0);
	if (elem.p == NULL)
		return -1;
	if (s->req.host.len > 0 && bst_is_token(s->req.host)) /* host=token, else quoted: keep simple */
		elem = cat(a, elem, ";host=", s->req.host);
	bst_str prev = trusted ? joined(in, BST_H_FORWARDED, ", ", a) : (bst_str){ "", 0 };
	bst_str v = prev.len > 0 ? cat(a, prev, ", ", elem) : elem;
	if (v.p == NULL || bst_headers_add(out, BST_S("Forwarded"), v) != 0)
		return -1;
	return 0;
}

/* Fields an upstream may use to steer a front server; hidden unless proxy_pass_header names them. */
static const char *const hidden_default[] = { "x-accel-redirect", "x-accel-buffering",
					      "x-accel-charset", "x-accel-limit-rate",
					      "x-accel-expires", NULL };

int bst_proxy_resp_headers(const bst_stream *s, const bst_headers *in, bst_headers *out)
{
	const bst_cfg_proxy *pc = &s->cfg->proxy;
	for (uint32_t i = 0; i < in->n; i++) {
		const bst_header *h = &in->v[i];
		if (is_hop_by_hop(h->id) || h->id == BST_H_DATE || h->id == BST_H_SERVER)
			continue;
		if (conn_lists(in, h->name) || name_listed(&pc->hide_headers, h->name))
			continue;
		bool hidden = false;
		for (const char *const *d = hidden_default; *d && !hidden; d++)
			hidden = bst_str_ieq(h->name, (bst_str){ *d, (uint32_t)strlen(*d) });
		if (hidden && !name_listed(&pc->pass_headers, h->name))
			continue;
		if (bst_headers_add(out, h->name, h->value) != 0)
			return -1;
	}
	return 0;
}

#include "http/validate_pseudo.h"

#include "http/token.h"

#include <string.h>

bool bst_pseudo_name_ok(bst_str n)
{
	if (n.len == 0)
		return false;
	uint32_t i = n.p[0] == ':' ? 1 : 0;
	if (i == 1 && n.len == 1)
		return false;
	for (; i < n.len; i++) {
		unsigned char c = (unsigned char)n.p[i];
		if (!bst_is_tchar(c) || (c >= 'A' && c <= 'Z')) /* HTTP/2 names are lower case */
			return false;
	}
	return true;
}

bool bst_pseudo_value_ok(bst_str v)
{
	if (!bst_is_field_value_clean(v))
		return false;
	if (v.len > 0 && (v.p[0] == ' ' || v.p[0] == '\t' || v.p[v.len - 1] == ' ' || v.p[v.len - 1] == '\t'))
		return false;
	return true;
}

/* Connection-specific fields have no meaning in HTTP/2 and are how a request gets smuggled into
 * an HTTP/1.1 hop (RFC 9113 section 8.2.2). */
static bool connection_specific(const bst_header *h)
{
	switch (h->id) {
	case BST_H_CONNECTION:
	case BST_H_KEEP_ALIVE:
	case BST_H_PROXY_CONNECTION:
	case BST_H_TRANSFER_ENCODING:
	case BST_H_UPGRADE:
		return true;
	default:
		return false;
	}
}

static bool path_chars_ok(bst_str p)
{
	for (uint32_t i = 0; i < p.len; i++)
		if ((unsigned char)p.p[i] <= 0x20 || (unsigned char)p.p[i] >= 0x7f || p.p[i] == '#')
			return false;
	return true;
}

static bool scheme_ok(bst_str s)
{
	if (s.len == 0 || !((s.p[0] | 32) >= 'a' && (s.p[0] | 32) <= 'z'))
		return false;
	for (uint32_t i = 1; i < s.len; i++) {
		char c = s.p[i];
		if (!(((c | 32) >= 'a' && (c | 32) <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'))
			return false;
	}
	return true;
}

bool bst_validate_trailer_fields(const bst_headers *in)
{
	for (uint32_t i = 0; i < in->n; i++) {
		const bst_header *h = &in->v[i];
		if (h->name.len > 0 && h->name.p[0] == ':')
			return false;
		if (!bst_pseudo_name_ok(h->name) || !bst_pseudo_value_ok(h->value) || connection_specific(h))
			return false;
	}
	return true;
}

bst_pseudo_rc bst_validate_pseudo_request(const bst_headers *in, bst_arena *arena, bst_req_head *out,
					  const bst_pseudo_opts *o, bst_pseudo_result *res)
{
	bst_str method = { 0 }, scheme = { 0 }, authority = { 0 }, path = { 0 }, protocol = { 0 };
	bool have_method = false, have_scheme = false, have_authority = false, have_path = false,
	     have_protocol = false, seen_regular = false;
	const bst_header *host = NULL, *first_cookie = NULL;
	size_t nhost = 0, ncookie = 0, cookie_bytes = 0;
	memset(res, 0, sizeof *res);

	for (uint32_t i = 0; i < in->n; i++) {
		const bst_header *h = &in->v[i];
		if (!bst_pseudo_name_ok(h->name) || !bst_pseudo_value_ok(h->value))
			return BST_PSEUDO_MALFORMED;
		if (h->name.p[0] == ':') {
			if (seen_regular) /* a pseudo-header after a regular field */
				return BST_PSEUDO_MALFORMED;
			bst_str n = h->name;
			if (bst_str_eq(n, BST_S(":method"))) {
				if (have_method)
					return BST_PSEUDO_MALFORMED;
				have_method = true, method = h->value;
			} else if (bst_str_eq(n, BST_S(":scheme"))) {
				if (have_scheme)
					return BST_PSEUDO_MALFORMED;
				have_scheme = true, scheme = h->value;
			} else if (bst_str_eq(n, BST_S(":authority"))) {
				if (have_authority)
					return BST_PSEUDO_MALFORMED;
				have_authority = true, authority = h->value;
			} else if (bst_str_eq(n, BST_S(":path"))) {
				if (have_path)
					return BST_PSEUDO_MALFORMED;
				have_path = true, path = h->value;
			} else if (bst_str_eq(n, BST_S(":protocol")) && o->allow_protocol) {
				if (have_protocol)
					return BST_PSEUDO_MALFORMED;
				have_protocol = true, protocol = h->value;
			} else { /* :status in a request, :protocol nobody asked for, or an unknown one */
				return BST_PSEUDO_MALFORMED;
			}
			continue;
		}
		seen_regular = true;
		if (connection_specific(h))
			return BST_PSEUDO_MALFORMED;
		if (h->id == BST_H_TE && !bst_str_eq(h->value, BST_S("trailers")))
			return BST_PSEUDO_MALFORMED;
		if (h->id == BST_H_HOST) {
			host = h;
			nhost++;
			continue;
		}
		if (h->id == BST_H_COOKIE) {
			if (ncookie++ == 0)
				first_cookie = h;
			cookie_bytes += h->value.len + 2;
			continue;
		}
		if (h->id == BST_H_CONTENT_LENGTH) {
			uint64_t v;
			if (!bst_str_to_u64(h->value, &v) || v > (uint64_t)INT64_MAX ||
			    (res->has_length && res->length != v))
				return BST_PSEUDO_MALFORMED; /* not a number, or two that disagree */
			res->has_length = true;
			res->length = v;
		}
	}

	if (!have_method || method.len == 0 || !bst_is_token(method))
		return BST_PSEUDO_MALFORMED;
	bst_method m = bst_method_from(method);
	bool connect = m == BST_M_CONNECT;
	bool ext_connect = connect && have_protocol;
	if (have_protocol && (!connect || protocol.len == 0))
		return BST_PSEUDO_MALFORMED;
	if (connect && !ext_connect) { /* RFC 9113 section 8.5: only :method and :authority */
		if (have_scheme || have_path || !have_authority || authority.len == 0)
			return BST_PSEUDO_MALFORMED;
	} else if (!have_scheme || !have_path || !scheme_ok(scheme) || path.len == 0) {
		return BST_PSEUDO_MALFORMED;
	}
	if (!connect || ext_connect) {
		bool star = m == BST_M_OPTIONS && bst_str_eq(path, BST_S("*"));
		if (!star && path.p[0] != '/')
			return BST_PSEUDO_MALFORMED;
		if (!path_chars_ok(path))
			return BST_PSEUDO_MALFORMED;
	}
	if (ext_connect && (!have_authority || authority.len == 0))
		return BST_PSEUDO_MALFORMED;
	if (res->has_length && o->end_stream && res->length != 0)
		return BST_PSEUDO_MALFORMED; /* announced content that never comes */

	/* Host and :authority name the same thing: when both are there they must agree. */
	if (nhost > 1 || (have_authority && authority.len == 0 && !connect && nhost == 0))
		return BST_PSEUDO_BAD_REQUEST;
	bst_str hostval = have_authority ? authority : (host != NULL ? host->value : (bst_str){ NULL, 0 });
	if (hostval.len == 0 || !bst_valid_authority(hostval, connect && !ext_connect))
		return BST_PSEUDO_BAD_REQUEST;
	if (have_authority && host != NULL && !bst_str_ieq(authority, host->value))
		return BST_PSEUDO_BAD_REQUEST;

	for (uint32_t i = 0; i < in->n; i++) {
		const bst_header *h = &in->v[i];
		if (h->name.p[0] == ':' || h->id == BST_H_HOST)
			continue;
		if (h->id == BST_H_COOKIE) { /* RFC 9113 section 8.2.3: crumbs rejoin into one field */
			if (h != first_cookie)
				continue;
			if (ncookie == 1) {
				if (bst_headers_add(&out->headers, h->name, h->value) != 0)
					return BST_PSEUDO_BAD_REQUEST;
				continue;
			}
			char *buf = bst_arena_alloc(arena, cookie_bytes);
			if (buf == NULL)
				return BST_PSEUDO_BAD_REQUEST;
			size_t len = 0;
			for (uint32_t k = i; k < in->n; k++)
				if (in->v[k].id == BST_H_COOKIE) {
					if (len > 0) {
						buf[len++] = ';';
						buf[len++] = ' ';
					}
					memcpy(buf + len, in->v[k].value.p, in->v[k].value.len);
					len += in->v[k].value.len;
				}
			if (bst_headers_add(&out->headers, h->name, (bst_str){ buf, (uint32_t)len }) != 0)
				return BST_PSEUDO_BAD_REQUEST;
			continue;
		}
		if (bst_headers_add(&out->headers, h->name, h->value) != 0)
			return BST_PSEUDO_BAD_REQUEST;
	}
	if (bst_headers_add(&out->headers, BST_S("host"), hostval) != 0)
		return BST_PSEUDO_BAD_REQUEST;

	out->method = m;
	out->method_str = method;
	out->version_minor = 1;
	out->scheme = scheme;
	out->authority = authority;
	if (connect && !ext_connect) {
		out->form = BST_TARGET_AUTHORITY;
		out->target = authority;
		out->authority = authority;
	} else {
		out->target = path;
		out->form = bst_str_eq(path, BST_S("*")) ? BST_TARGET_ASTERISK : BST_TARGET_ORIGIN;
		const char *q = memchr(path.p, '?', path.len);
		out->path = q != NULL ? (bst_str){ path.p, (uint32_t)(q - path.p) } : path;
		if (q != NULL) {
			out->has_query = true;
			out->query = (bst_str){ q + 1, (uint32_t)(path.len - (uint32_t)(q - path.p) - 1) };
		}
	}
	res->protocol = protocol;
	return BST_PSEUDO_OK;
}

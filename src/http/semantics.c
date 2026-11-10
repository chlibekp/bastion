#include "http/semantics.h"

#include "http/token.h"

#include <string.h>

bool bst_valid_authority(bst_str a, bool need_port)
{
	size_t i = 0;
	if (a.len == 0)
		return false;
	if (a.p[0] == '[') { /* IP-literal: hex digits, colons and dots only */
		const char *rb = memchr(a.p, ']', a.len);
		if (rb == NULL || rb - a.p < 3)
			return false;
		for (const char *c = a.p + 1; c < rb; c++)
			if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f') ||
			      (*c >= 'A' && *c <= 'F') || *c == ':' || *c == '.'))
				return false;
		i = (size_t)(rb - a.p) + 1;
	} else {
		for (; i < a.len && a.p[i] != ':'; i++) {
			unsigned char c = (unsigned char)a.p[i];
			bool ok = (c >= '0' && c <= '9') || ((c | 32) >= 'a' && (c | 32) <= 'z') ||
				  (c != 0 && strchr("-._~%!$&'()*+,;=", c) != NULL);
			if (!ok)
				return false;
		}
		if (i == 0)
			return false;
	}
	if (i == a.len)
		return !need_port;
	if (a.p[i] != ':')
		return false;
	i++;
	if (i == a.len)
		return !need_port;
	if (a.len - i > 5)
		return false;
	for (; i < a.len; i++)
		if (a.p[i] < '0' || a.p[i] > '9')
			return false;
	return true;
}

/* Walks the comma-separated tokens of every line of a list header. False on a malformed item. */
typedef struct conn_flags {
	bool close, keep_alive;
} conn_flags;

static bool scan_connection(const bst_headers *h, conn_flags *f)
{
	for (const bst_header *e = bst_headers_get(h, BST_H_CONNECTION); e;
	     e = bst_headers_next(h, e, BST_H_CONNECTION)) {
		bst_str v = e->value;
		for (;;) {
			const char *comma = memchr(v.p, ',', v.len);
			bst_str item = { v.p, comma ? (uint32_t)(comma - v.p) : v.len };
			while (item.len > 0 && (item.p[0] == ' ' || item.p[0] == '\t'))
				item.p++, item.len--;
			while (item.len > 0 && (item.p[item.len - 1] == ' ' || item.p[item.len - 1] == '\t'))
				item.len--;
			if (item.len > 0) { /* empty list elements are legal (RFC 9110 section 5.6.1.2) */
				if (!bst_is_token(item))
					return false;
				if (bst_str_ieq(item, BST_S("close")))
					f->close = true;
				else if (bst_str_ieq(item, BST_S("keep-alive")))
					f->keep_alive = true;
			}
			if (comma == NULL)
				break;
			v = (bst_str){ comma + 1, (uint32_t)(v.len - (uint32_t)(comma + 1 - v.p)) };
		}
	}
	return true;
}

int bst_validate_request_semantics(bst_req *r)
{
	const bst_req_head *h = &r->head;
	size_t nhost = bst_headers_count(&h->headers, BST_H_HOST);

	/* Host (RFC 9112 section 3.2): one, valid, on every HTTP/1.1 request. */
	if (nhost > 1 || (nhost == 0 && h->version_minor >= 1))
		return 400;
	if (nhost == 1) {
		bst_str v = bst_headers_get(&h->headers, BST_H_HOST)->value;
		if (!bst_valid_authority(v, false))
			return 400;
		r->host = v;
	} else {
		r->host = (bst_str){ NULL, 0 };
	}
	if (h->form == BST_TARGET_ABSOLUTE || h->form == BST_TARGET_AUTHORITY)
		r->host = h->authority; /* the target wins over a Host that says otherwise */

	conn_flags f = { 0 };
	if (!scan_connection(&h->headers, &f))
		return 400;
	r->keepalive = h->version_minor >= 1 ? !f.close : (f.keep_alive && !f.close);

	r->expect_continue = false;
	const bst_header *ex = bst_headers_get(&h->headers, BST_H_EXPECT);
	if (ex != NULL && h->version_minor >= 1) {
		if (!bst_str_ieq(ex->value, BST_S("100-continue")) ||
		    bst_headers_count(&h->headers, BST_H_EXPECT) > 1)
			return 417;
		r->expect_continue = true;
	}

	switch (h->method) {
	case BST_M_TRACE:
	case BST_M_CONNECT:
		return 405;
	case BST_M_UNKNOWN:
		return 501;
	default:
		return 0;
	}
}

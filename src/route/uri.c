#include "route/uri.h"

#include <stdbool.h>
#include <string.h>

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Percent-decoding and slash merging into out; w never passes r, so out may be the input. */
static int decode(bst_str in, char *out, bst_uri_flags flags, size_t *n)
{
	size_t w = 0;
	for (size_t r = 0; r < in.len;) {
		unsigned char c = (unsigned char)in.p[r];
		if (c == '%') {
			if (r + 2 >= in.len)
				return BST_URI_E_PERCENT;
			int hi = hexval(in.p[r + 1]), lo = hexval(in.p[r + 2]);
			if (hi < 0 || lo < 0)
				return BST_URI_E_PERCENT;
			c = (unsigned char)(hi * 16 + lo);
			r += 3;
			if (c == 0)
				return BST_URI_E_NUL;
			if (c == '/' && !(flags & BST_URI_ALLOW_ENCODED_SLASH))
				return BST_URI_E_SLASH;
		} else {
			if (c == 0)
				return BST_URI_E_NUL;
			r++;
		}
		if (c == '/' && (flags & BST_URI_MERGE_SLASHES) && w > 0 && out[w - 1] == '/')
			continue;
		out[w++] = (char)c;
	}
	*n = w;
	return BST_URI_OK;
}

/* RFC 3986 section 5.2.4 on an absolute path, in place. w never passes r. */
static size_t remove_dots(char *p, size_t n)
{
	size_t r = 0, w = 0;
	while (r < n) { /* p[r] is '/' */
		size_t s = r + 1, e = s;
		while (e < n && p[e] != '/')
			e++;
		size_t slen = e - s;
		bool last = e == n;
		if (slen == 1 && p[s] == '.') {
			if (last)
				p[w++] = '/';
		} else if (slen == 2 && p[s] == '.' && p[s + 1] == '.') {
			while (w > 0) { /* drop the last output segment, never the root */
				w--;
				if (p[w] == '/')
					break;
			}
			if (last)
				p[w++] = '/';
		} else {
			p[w] = '/';
			memmove(p + w + 1, p + s, slen);
			w += 1 + slen;
		}
		r = e;
	}
	if (w == 0)
		p[w++] = '/';
	return w;
}

int bst_uri_normalize(bst_str raw, char *out, size_t cap, bst_uri_flags flags, size_t *out_len)
{
	if (raw.len == 0 || raw.p[0] != '/')
		return BST_URI_E_FORM;
	if (cap < (size_t)raw.len + 1)
		return BST_URI_E_SPACE;
	size_t n = 0;
	int rc = decode(raw, out, flags, &n);
	if (rc != BST_URI_OK)
		return rc;
	n = remove_dots(out, n);
	out[n] = '\0';
	*out_len = n;
	return BST_URI_OK;
}

static bool keep_raw(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
	       strchr("-._~/!$&'()*+,;=:@", c) != NULL;
}

int bst_uri_encode_path(bst_str in, char *out, size_t cap, size_t *out_len)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t w = 0;
	for (size_t i = 0; i < in.len; i++) {
		unsigned char c = (unsigned char)in.p[i];
		size_t need = keep_raw(c) && c != 0 ? 1 : 3;
		if (w + need + 1 > cap)
			return -1;
		if (need == 1) {
			out[w++] = (char)c;
		} else {
			out[w++] = '%';
			out[w++] = hex[c >> 4];
			out[w++] = hex[c & 15];
		}
	}
	out[w] = '\0';
	*out_len = w;
	return 0;
}

int bst_query_get(bst_str query, bst_str name, bst_str *value)
{
	size_t i = 0;
	while (i <= query.len && name.len > 0) {
		size_t e = i;
		while (e < query.len && query.p[e] != '&')
			e++;
		size_t eq = i;
		while (eq < e && query.p[eq] != '=')
			eq++;
		if (eq - i == name.len && memcmp(query.p + i, name.p, name.len) == 0) {
			size_t vs = eq < e ? eq + 1 : e;
			*value = (bst_str){ query.p + vs, (uint32_t)(e - vs) };
			return 1;
		}
		i = e + 1;
	}
	return 0;
}

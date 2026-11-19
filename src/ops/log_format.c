/* See log_format.h. */
#include "ops/log_format.h"

#include "core/json_utf8.h"

#include <stdint.h>
#include <string.h>

static const char hex[] = "0123456789abcdef";

/* A code point that must not appear raw in a log line even though it is valid UTF-8. */
static bool hostile_cp(uint32_t cp)
{
	return (cp >= 0x80 && cp <= 0x9f) || cp == 0x2028 || cp == 0x2029;
}

size_t bst_logfmt_json_esc(char *out, size_t cap, const char *p, size_t n)
{
	const unsigned char *s = (const unsigned char *)p, *end = s + n;
	size_t w = 0;
	while (s < end) {
		char tmp[6];
		const char *src = tmp;
		size_t len;
		uint32_t cp = 0;
		unsigned char c = *s;
		if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') {
			tmp[0] = (char)c;
			len = 1;
			s++;
		} else if (c == '"' || c == '\\') {
			tmp[0] = '\\';
			tmp[1] = (char)c;
			len = 2;
			s++;
		} else if (c < 0x80) { /* control bytes and DEL */
			const char *sh = c == '\n' ? "\\n" : c == '\r' ? "\\r" : c == '\t' ? "\\t" : NULL;
			if (sh != NULL) {
				src = sh;
				len = 2;
			} else {
				memcpy(tmp, "\\u00", 4);
				tmp[4] = hex[c >> 4];
				tmp[5] = hex[c & 15];
				len = 6;
			}
			s++;
		} else {
			size_t k = utf8_next(s, end, &cp);
			if (k == 0) { /* not UTF-8: one byte becomes U+FFFD */
				src = "\\ufffd";
				len = 6;
				s++;
			} else if (hostile_cp(cp)) {
				memcpy(tmp, "\\u", 2);
				tmp[2] = hex[(cp >> 12) & 15];
				tmp[3] = hex[(cp >> 8) & 15];
				tmp[4] = hex[(cp >> 4) & 15];
				tmp[5] = hex[cp & 15];
				len = 6;
				s += k;
			} else {
				src = (const char *)s;
				len = k;
				s += k;
			}
		}
		if (cap - w < len)
			return SIZE_MAX;
		memcpy(out + w, src, len);
		w += len;
	}
	return w;
}

static size_t put_x(char *out, size_t cap, size_t w, unsigned char c)
{
	if (cap - w < 4)
		return SIZE_MAX;
	out[w] = '\\';
	out[w + 1] = 'x';
	out[w + 2] = hex[c >> 4];
	out[w + 3] = hex[c & 15];
	return w + 4;
}

size_t bst_logfmt_text_esc(char *out, size_t cap, const char *p, size_t n)
{
	const unsigned char *s = (const unsigned char *)p, *end = s + n;
	size_t w = 0;
	while (s < end) {
		unsigned char c = *s;
		uint32_t cp = 0;
		size_t k = 0;
		if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') {
			if (w == cap)
				return SIZE_MAX;
			out[w++] = (char)c;
			s++;
		} else if (c < 0x80 || (k = utf8_next(s, end, &cp)) == 0) {
			if ((w = put_x(out, cap, w, c)) == SIZE_MAX)
				return SIZE_MAX;
			s++;
		} else if (hostile_cp(cp)) {
			for (size_t i = 0; i < k; i++)
				if ((w = put_x(out, cap, w, s[i])) == SIZE_MAX)
					return SIZE_MAX;
			s += k;
		} else {
			if (cap - w < k)
				return SIZE_MAX;
			memcpy(out + w, s, k);
			w += k;
			s += k;
		}
	}
	return w;
}

size_t bst_logfmt_text_lit(char *out, size_t cap, const char *p, size_t n)
{
	size_t w = 0;
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)p[i];
		if (c < 0x20 || c == 0x7f) {
			if ((w = put_x(out, cap, w, c)) == SIZE_MAX)
				return SIZE_MAX;
		} else {
			if (w == cap)
				return SIZE_MAX;
			out[w++] = (char)c;
		}
	}
	return w;
}

static bool put(char *out, size_t cap, size_t *w, const char *s, size_t n)
{
	if (cap - *w < n)
		return false;
	memcpy(out + *w, s, n);
	*w += n;
	return true;
}

size_t bst_logfmt_render(const bst_logfmt *f, const bst_var_ctx *ctx, char *out, size_t cap)
{
	if (cap < 2)
		return 0;
	size_t room = cap - 1; /* the newline */
	size_t w = 0;
	if (!f->json) {
		w = bst_tpl_write(f->text, ctx, bst_logfmt_text_lit, bst_logfmt_text_esc,
				  BST_LOG_VALUE_MAX, out, room);
		if (w == SIZE_MAX)
			return 0;
	} else {
		if (!put(out, room, &w, "{", 1))
			return 0;
		for (size_t i = 0; i < f->nfields; i++) {
			const bst_logfmt_field *fl = &f->fields[i];
			if ((i > 0 && !put(out, room, &w, ",", 1)) || !put(out, room, &w, "\"", 1))
				return 0;
			size_t r = bst_logfmt_json_esc(out + w, room - w, fl->name, strlen(fl->name));
			if (r == SIZE_MAX)
				return 0;
			w += r;
			if (!put(out, room, &w, "\":\"", 3))
				return 0;
			r = bst_tpl_write(fl->tpl, ctx, bst_logfmt_json_esc, bst_logfmt_json_esc,
					  BST_LOG_VALUE_MAX, out + w, room - w);
			if (r == SIZE_MAX)
				return 0;
			w += r;
			if (!put(out, room, &w, "\"", 1))
				return 0;
		}
		if (!put(out, room, &w, "}", 1))
			return 0;
	}
	out[w++] = '\n';
	return w;
}

/* Internal: strict UTF-8 helpers shared by the JSON parser and writer. */
#ifndef BST_JSON_UTF8_H
#define BST_JSON_UTF8_H

#include <stddef.h>
#include <stdint.h>

/* Decodes one scalar from [p, end). Returns bytes consumed, or 0 if malformed. */
static inline size_t utf8_next(const unsigned char *p, const unsigned char *end, uint32_t *cp)
{
	unsigned char c = p[0];
	size_t need;
	uint32_t v, lo = 0x80, hi = 0xbf;
	if (c < 0x80) {
		*cp = c;
		return 1;
	} else if (c >= 0xc2 && c <= 0xdf) {
		need = 1;
		v = c & 0x1fu;
	} else if (c >= 0xe0 && c <= 0xef) {
		need = 2;
		v = c & 0x0fu;
		if (c == 0xe0)
			lo = 0xa0;
		if (c == 0xed)
			hi = 0x9f; /* no UTF-8 encoded surrogates */
	} else if (c >= 0xf0 && c <= 0xf4) {
		need = 3;
		v = c & 0x07u;
		if (c == 0xf0)
			lo = 0x90;
		if (c == 0xf4)
			hi = 0x8f; /* nothing above U+10FFFF */
	} else {
		return 0;
	}
	if ((size_t)(end - p) < need + 1)
		return 0;
	for (size_t i = 1; i <= need; i++) {
		unsigned char d = p[i];
		if (d < lo || d > hi)
			return 0;
		lo = 0x80;
		hi = 0xbf;
		v = (v << 6) | (d & 0x3fu);
	}
	*cp = v;
	return need + 1;
}

static inline size_t utf8_put(unsigned char *o, uint32_t cp)
{
	if (cp < 0x80) {
		o[0] = (unsigned char)cp;
		return 1;
	}
	if (cp < 0x800) {
		o[0] = (unsigned char)(0xc0 | (cp >> 6));
		o[1] = (unsigned char)(0x80 | (cp & 0x3f));
		return 2;
	}
	if (cp < 0x10000) {
		o[0] = (unsigned char)(0xe0 | (cp >> 12));
		o[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
		o[2] = (unsigned char)(0x80 | (cp & 0x3f));
		return 3;
	}
	o[0] = (unsigned char)(0xf0 | (cp >> 18));
	o[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3f));
	o[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
	o[3] = (unsigned char)(0x80 | (cp & 0x3f));
	return 4;
}

#endif

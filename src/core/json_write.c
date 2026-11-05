#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/json.h"
#include "core/json_utf8.h"

/* ---- writer ---- */

static bool jw_reserve(bst_jw *w, size_t extra)
{
	if (w->err)
		return false;
	if (extra > SIZE_MAX - w->len - 1) {
		w->err = true;
		return false;
	}
	size_t need = w->len + extra + 1;
	if (need <= w->cap)
		return true;
	size_t cap = w->cap ? w->cap : 64;
	while (cap < need) {
		if (cap > SIZE_MAX / 2) {
			w->err = true;
			return false;
		}
		cap *= 2;
	}
	char *nb = realloc(w->buf, cap);
	if (!nb) {
		w->err = true;
		return false;
	}
	w->buf = nb;
	w->cap = cap;
	return true;
}

static void jw_put(bst_jw *w, const char *s, size_t n)
{
	if (!jw_reserve(w, n))
		return;
	memcpy(w->buf + w->len, s, n);
	w->len += n;
	w->buf[w->len] = '\0';
}

/* Comma and key bookkeeping before a value or key. */
static void jw_pre(bst_jw *w)
{
	if (w->after_key) {
		w->after_key = false;
		return;
	}
	if (w->depth > 0) {
		if (!w->first[w->depth - 1])
			jw_put(w, ",", 1);
		w->first[w->depth - 1] = false;
	}
}

void bst_jw_init(bst_jw *w)
{
	memset(w, 0, sizeof *w);
}

void bst_jw_free(bst_jw *w)
{
	free(w->buf);
	memset(w, 0, sizeof *w);
}

bool bst_jw_finish(bst_jw *w)
{
	if (w->depth != 0 || w->after_key)
		w->err = true;
	if (!w->err && !w->buf && !jw_reserve(w, 0))
		return false;
	return !w->err;
}

static void jw_open(bst_jw *w, char ch)
{
	if (w->err)
		return;
	if (w->depth >= BST_JSON_MAX_DEPTH) {
		w->err = true;
		return;
	}
	jw_pre(w);
	jw_put(w, &ch, 1);
	w->first[w->depth++] = true;
}

static void jw_close(bst_jw *w, char ch)
{
	if (w->err)
		return;
	if (w->depth == 0 || w->after_key) {
		w->err = true;
		return;
	}
	w->depth--;
	jw_put(w, &ch, 1);
}

void bst_jw_obj_begin(bst_jw *w) { jw_open(w, '{'); }
void bst_jw_obj_end(bst_jw *w) { jw_close(w, '}'); }
void bst_jw_arr_begin(bst_jw *w) { jw_open(w, '['); }
void bst_jw_arr_end(bst_jw *w) { jw_close(w, ']'); }

static void jw_string(bst_jw *w, bst_str s)
{
	static const char hex[] = "0123456789abcdef";
	/* Validate first so a bad string leaves no partial output behind. */
	const unsigned char *p = (const unsigned char *)s.p, *end = p + s.len;
	size_t out = 2;
	for (const unsigned char *q = p; q < end;) {
		uint32_t cp;
		size_t k = utf8_next(q, end, &cp);
		if (k == 0 || cp == 0) {
			w->err = true;
			return;
		}
		out += (cp < 0x20) ? 6 : (k == 1 && (cp == '"' || cp == '\\') ? 2 : k);
		q += k;
	}
	if (!jw_reserve(w, out))
		return;
	char *o = w->buf + w->len;
	*o++ = '"';
	for (const unsigned char *q = p; q < end; q++) {
		unsigned char ch = *q;
		switch (ch) {
		case '"': *o++ = '\\'; *o++ = '"'; break;
		case '\\': *o++ = '\\'; *o++ = '\\'; break;
		case '\n': *o++ = '\\'; *o++ = 'n'; break;
		case '\r': *o++ = '\\'; *o++ = 'r'; break;
		case '\t': *o++ = '\\'; *o++ = 't'; break;
		case '\b': *o++ = '\\'; *o++ = 'b'; break;
		case '\f': *o++ = '\\'; *o++ = 'f'; break;
		default:
			if (ch < 0x20) {
				memcpy(o, "\\u00", 4);
				o += 4;
				*o++ = hex[ch >> 4];
				*o++ = hex[ch & 15];
			} else {
				*o++ = (char)ch;
			}
		}
	}
	*o++ = '"';
	w->len = (size_t)(o - w->buf);
	w->buf[w->len] = '\0';
}

void bst_jw_key(bst_jw *w, bst_str k)
{
	if (w->err)
		return;
	if (w->depth == 0 || w->after_key) {
		w->err = true;
		return;
	}
	jw_pre(w);
	jw_string(w, k);
	jw_put(w, ":", 1);
	w->after_key = true;
}

void bst_jw_str(bst_jw *w, bst_str s)
{
	if (w->err)
		return;
	jw_pre(w);
	jw_string(w, s);
}

void bst_jw_int(bst_jw *w, int64_t v)
{
	char tmp[24];
	size_t n = 0;
	uint64_t u = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
	do {
		tmp[sizeof tmp - 1 - n++] = (char)('0' + u % 10);
		u /= 10;
	} while (u);
	if (v < 0)
		tmp[sizeof tmp - 1 - n++] = '-';
	if (w->err)
		return;
	jw_pre(w);
	jw_put(w, tmp + sizeof tmp - n, n);
}

void bst_jw_bool(bst_jw *w, bool v)
{
	if (w->err)
		return;
	jw_pre(w);
	jw_put(w, v ? "true" : "false", v ? 4 : 5);
}

void bst_jw_null(bst_jw *w)
{
	if (w->err)
		return;
	jw_pre(w);
	jw_put(w, "null", 4);
}

void bst_jw_value(bst_jw *w, const bst_json *j)
{
	if (w->err)
		return;
	if (!j) {
		w->err = true;
		return;
	}
	bool b;
	bst_str t;
	switch (bst_json_typeof(j)) {
	case BST_JSON_NULL:
		bst_jw_null(w);
		break;
	case BST_JSON_BOOL:
		if (bst_json_bool(j, &b))
			bst_jw_bool(w, b);
		break;
	case BST_JSON_NUM:
		if (bst_json_num_text(j, &t)) {
			jw_pre(w);
			jw_put(w, t.p, t.len);
		}
		break;
	case BST_JSON_STR:
		if (bst_json_str(j, &t))
			bst_jw_str(w, t);
		break;
	case BST_JSON_ARR:
		bst_jw_arr_begin(w);
		for (size_t i = 0; i < bst_json_arr_len(j); i++)
			bst_jw_value(w, bst_json_arr_at(j, i));
		bst_jw_arr_end(w);
		break;
	case BST_JSON_OBJ:
		bst_jw_obj_begin(w);
		for (size_t i = 0; i < bst_json_arr_len(j); i++) {
			bst_json_obj_at(j, i, &t);
			bst_jw_key(w, t);
			bst_jw_value(w, bst_json_obj_at(j, i, NULL));
		}
		bst_jw_obj_end(w);
		break;
	}
}

/* See cache_control.h. */
#include "http/cache_control.h"

#include "http/token.h"

#include <string.h>

#define DELTA_MAX 2147483648LL /* RFC 9111 section 1.2.2 */

void bst_cc_init(bst_cache_control *cc)
{
	memset(cc, 0, sizeof *cc);
	cc->max_age = cc->s_maxage = cc->max_stale = cc->min_fresh = cc->swr = cc->sie = BST_CC_NONE;
}

static bool ows(char c)
{
	return c == ' ' || c == '\t';
}

/* delta-seconds: 1 to 10 digits, at most 2^31. -1 when malformed. */
static int64_t delta(bst_str v)
{
	if (v.len == 0 || v.len > 10)
		return -1;
	int64_t n = 0;
	for (uint32_t i = 0; i < v.len; i++) {
		if (v.p[i] < '0' || v.p[i] > '9')
			return -1;
		n = n * 10 + (v.p[i] - '0');
	}
	return n > DELTA_MAX ? -1 : n;
}

static void set_delta(bst_cache_control *cc, int64_t *slot, bst_str v, bool has_v)
{
	int64_t d = has_v ? delta(v) : -1;
	if (d < 0) {
		cc->invalid = true;
		return;
	}
	if (*slot != BST_CC_NONE && *slot != d)
		cc->invalid = true; /* two values: stale (RFC 9111 section 4.2.1) */
	*slot = d;
}

static void apply(bst_cache_control *cc, bst_str name, bst_str v, bool has_v)
{
#define IS(lit) bst_str_ieq(name, BST_S(lit))
	if (IS("no-store"))
		cc->no_store = true;
	else if (IS("no-cache"))
		cc->no_cache = true; /* the qualified form counts as unqualified: stricter */
	else if (IS("private"))
		cc->priv = true;
	else if (IS("public"))
		cc->pub = true;
	else if (IS("must-revalidate"))
		cc->must_revalidate = true;
	else if (IS("proxy-revalidate"))
		cc->proxy_revalidate = true;
	else if (IS("immutable"))
		cc->immutable = true;
	else if (IS("no-transform"))
		cc->no_transform = true;
	else if (IS("only-if-cached"))
		cc->only_if_cached = true;
	else if (IS("max-age"))
		set_delta(cc, &cc->max_age, v, has_v);
	else if (IS("s-maxage"))
		set_delta(cc, &cc->s_maxage, v, has_v);
	else if (IS("min-fresh"))
		set_delta(cc, &cc->min_fresh, v, has_v);
	else if (IS("stale-while-revalidate"))
		set_delta(cc, &cc->swr, v, has_v);
	else if (IS("stale-if-error"))
		set_delta(cc, &cc->sie, v, has_v);
	else if (IS("max-stale")) {
		if (!has_v)
			cc->max_stale_any = true;
		else
			set_delta(cc, &cc->max_stale, v, has_v);
	}
#undef IS
}

void bst_cc_parse_value(bst_str v, bst_cache_control *cc)
{
	cc->present = true;
	uint32_t i = 0, n = v.len;
	const char *p = v.p;
	while (i < n) {
		while (i < n && (ows(p[i]) || p[i] == ','))
			i++;
		uint32_t ns = i;
		while (i < n && bst_is_tchar((unsigned char)p[i]))
			i++;
		bst_str name = { p + ns, i - ns };
		while (i < n && ows(p[i]))
			i++;
		bst_str val = { p + i, 0 };
		bool has_v = false, bad = name.len == 0;
		if (i < n && p[i] == '=') {
			i++;
			while (i < n && ows(p[i]))
				i++;
			has_v = true;
			if (i < n && p[i] == '"') {
				i++;
				uint32_t vs = i;
				while (i < n && p[i] != '"') {
					if (p[i] == '\\' && i + 1 < n)
						i++;
					i++;
				}
				if (i >= n)
					bad = true; /* unterminated */
				val = (bst_str){ p + vs, i - vs };
				if (i < n)
					i++;
			} else {
				uint32_t vs = i;
				while (i < n && bst_is_tchar((unsigned char)p[i]))
					i++;
				val = (bst_str){ p + vs, i - vs };
			}
		}
		while (i < n && ows(p[i]))
			i++;
		if (i < n && p[i] != ',') {
			bad = true; /* junk in the element: skip to the next comma */
			while (i < n && p[i] != ',')
				i++;
		}
		if (!bad)
			apply(cc, name, val, has_v);
		else if (name.len > 0 && has_v)
			apply(cc, name, (bst_str){ "x", 1 }, true); /* a broken known delta is invalid */
	}
}

bool bst_cc_parse_name(const bst_headers *h, bst_str name, bst_cache_control *cc)
{
	bst_cc_init(cc);
	for (const bst_header *f = bst_headers_next_name(h, NULL, name); f != NULL;
	     f = bst_headers_next_name(h, f, name))
		bst_cc_parse_value(f->value, cc);
	return cc->present;
}

bool bst_cc_parse(const bst_headers *h, bst_cache_control *cc)
{
	bst_cc_init(cc);
	for (const bst_header *f = bst_headers_next(h, NULL, BST_H_CACHE_CONTROL); f != NULL;
	     f = bst_headers_next(h, f, BST_H_CACHE_CONTROL))
		bst_cc_parse_value(f->value, cc);
	return cc->present;
}

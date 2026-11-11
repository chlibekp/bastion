#include "http/conditional.h"

#include <stdio.h>
#include <string.h>

/* ---- entity tags ---- */

typedef struct tag {
	bool weak;
	const char *op; /* the opaque part with its quotes */
	size_t oplen;
} tag;

static bool ows(char c)
{
	return c == ' ' || c == '\t';
}

/* Parses one entity-tag at *p; false on a malformed one. */
static bool tag_at(const char **p, const char *end, tag *t)
{
	const char *s = *p;
	t->weak = false;
	if (end - s >= 2 && s[0] == 'W' && s[1] == '/') {
		t->weak = true;
		s += 2;
	}
	if (s >= end || *s != '"')
		return false;
	const char *q = s + 1;
	while (q < end && *q != '"') {
		unsigned char c = (unsigned char)*q;
		if (c < 0x21 || c == 0x7f)
			return false; /* etagc: no controls, no space */
		q++;
	}
	if (q >= end)
		return false;
	t->op = s;
	t->oplen = (size_t)(q + 1 - s);
	*p = q + 1;
	return true;
}

/* Does the list (a header value) hold a tag equal to mine? strong: neither may be weak. "*" matches
 * anything. A malformed list matches nothing. */
static bool list_has(bst_str list, const tag *mine, bool strong, bool *star)
{
	const char *p = list.p, *end = list.p + list.len;
	bool hit = false;
	for (;;) {
		while (p < end && (ows(*p) || *p == ','))
			p++;
		if (p >= end)
			return hit;
		if (*p == '*') {
			*star = true;
			p++;
			continue;
		}
		tag t;
		if (!tag_at(&p, end, &t))
			return false;
		if (mine != NULL && t.oplen == mine->oplen && memcmp(t.op, mine->op, t.oplen) == 0 &&
		    !(strong && (t.weak || mine->weak)))
			hit = true;
		while (p < end && ows(*p))
			p++;
		if (p < end && *p != ',')
			return false;
	}
}

static bool parse_mine(const bst_validators *v, tag *t)
{
	if (!v->has_etag)
		return false;
	const char *p = v->etag.p;
	return tag_at(&p, v->etag.p + v->etag.len, t);
}

/* Any line of the header matching (or "*"). present is set when the header exists at all. */
static bool header_matches(const bst_headers *h, bst_hdr_id id, const bst_validators *v, bool strong,
			   bool *present)
{
	tag mine;
	bool have = parse_mine(v, &mine);
	bool star = false, hit = false;
	const bst_header *e = NULL;
	*present = false;
	while ((e = bst_headers_next(h, e, id)) != NULL) {
		*present = true;
		if (list_has(e->value, have ? &mine : NULL, strong, &star))
			hit = true;
	}
	return hit || star;
}

/* ---- dates ---- */

static int digits(const char *p, int n)
{
	int v = 0;
	for (int i = 0; i < n; i++) {
		if (p[i] < '0' || p[i] > '9')
			return -1;
		v = v * 10 + (p[i] - '0');
	}
	return v;
}

static const char *const mon[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
				   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

static int month_of(const char *p)
{
	for (int i = 0; i < 12; i++)
		if (memcmp(p, mon[i], 3) == 0)
			return i + 1;
	return 0;
}

static bool mk_time(int y, int mo, int d, int h, int mi, int s, time_t *out)
{
	static const int mdays[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	if (y < 1970 || mo < 1 || mo > 12 || d < 1 || h < 0 || h > 23 || mi < 0 || mi > 59 ||
	    s < 0 || s > 60)
		return false;
	bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
	if (d > mdays[mo - 1] + (mo == 2 && leap))
		return false;
	long long yy = y - (mo <= 2);
	long long era = yy / 400, yoe = yy - era * 400;
	long long doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
	long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	long long days = era * 146097 + doe - 719468;
	*out = (time_t)(days * 86400 + h * 3600 + mi * 60 + (s == 60 ? 59 : s));
	return true;
}

bool bst_http_date_parse(bst_str in, time_t *out)
{
	const char *p = in.p;
	size_t n = in.len;
	while (n > 0 && ows(p[n - 1]))
		n--;
	while (n > 0 && ows(*p)) {
		p++;
		n--;
	}
	/* IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT" */
	if (n == 29 && p[3] == ',' && p[4] == ' ' && p[7] == ' ' && p[11] == ' ' && p[16] == ' ' &&
	    p[19] == ':' && p[22] == ':' && memcmp(p + 25, " GMT", 4) == 0)
		return mk_time(digits(p + 12, 4), month_of(p + 8), digits(p + 5, 2),
			       digits(p + 17, 2), digits(p + 20, 2), digits(p + 23, 2), out);
	/* asctime: "Sun Nov  6 08:49:37 1994" */
	if (n == 24 && p[3] == ' ' && p[7] == ' ' && p[10] == ' ' && p[13] == ':' && p[16] == ':' &&
	    p[19] == ' ') {
		int d = p[8] == ' ' ? digits(p + 9, 1) : digits(p + 8, 2);
		return mk_time(digits(p + 20, 4), month_of(p + 4), d, digits(p + 11, 2),
			       digits(p + 14, 2), digits(p + 17, 2), out);
	}
	/* RFC 850: "Sunday, 06-Nov-94 08:49:37 GMT" (a two-digit year: 70-99 is 19xx, else 20xx) */
	const char *comma = memchr(p, ',', n);
	if (comma != NULL && comma - p >= 6 && comma - p <= 9) {
		const char *q = comma + 1;
		size_t rest = n - (size_t)(q - p);
		if (rest == 23 && q[0] == ' ' && q[3] == '-' && q[7] == '-' && q[10] == ' ' &&
		    q[13] == ':' && q[16] == ':' && memcmp(q + 19, " GMT", 4) == 0) {
			int yy = digits(q + 8, 2);
			if (yy < 0)
				return false;
			return mk_time(yy >= 70 ? 1900 + yy : 2000 + yy, month_of(q + 4), digits(q + 1, 2),
				       digits(q + 11, 2), digits(q + 14, 2), digits(q + 17, 2), out);
		}
	}
	return false;
}

/* ---- evaluation ---- */

static bool header_date(const bst_headers *h, bst_hdr_id id, time_t *t)
{
	const bst_header *e = bst_headers_get(h, id);
	if (e == NULL || bst_headers_next(h, e, id) != NULL) /* repeated: ignored (13.1.3) */
		return false;
	return bst_http_date_parse(e->value, t);
}

bst_cond_result bst_evaluate_preconditions(const bst_headers *h, const bst_validators *v,
					   bst_method m)
{
	bool present;
	bool get_head = m == BST_M_GET || m == BST_M_HEAD;
	/* 1. If-Match: false is 412. A weak or missing validator never matches. */
	bool ok = header_matches(h, BST_H_IF_MATCH, v, true, &present);
	if (present) {
		if (!ok)
			return BST_COND_412;
	} else {
		/* 2. If-Unmodified-Since, only when there is no If-Match. */
		time_t d;
		if (v->has_mtime && header_date(h, BST_H_IF_UNMODIFIED_SINCE, &d) && v->mtime > d)
			return BST_COND_412;
	}
	/* 3. If-None-Match: a weak match fails it; GET and HEAD answer 304, the rest 412. */
	ok = header_matches(h, BST_H_IF_NONE_MATCH, v, false, &present);
	if (present) {
		if (ok)
			return get_head ? BST_COND_304 : BST_COND_412;
		return BST_COND_PROCEED; /* 4 applies only without If-None-Match */
	}
	/* 4. If-Modified-Since: GET and HEAD only. */
	time_t d;
	if (get_head && v->has_mtime && header_date(h, BST_H_IF_MODIFIED_SINCE, &d) && v->mtime <= d)
		return BST_COND_304;
	return BST_COND_PROCEED;
}

size_t bst_etag_format(int64_t mtime_ns, int64_t size, char *out, size_t cap)
{
	int n = snprintf(out, cap, "\"%llx-%llx\"", (unsigned long long)mtime_ns,
			 (unsigned long long)size);
	return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

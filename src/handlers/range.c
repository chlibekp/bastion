#include "handlers/range.h"

#include "http/conditional.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define NUM_MAX INT64_MAX

static bool ows(char c)
{
	return c == ' ' || c == '\t';
}

/* Digits at *p to a saturating value; false when there is none. */
static bool num(const char **p, const char *end, int64_t *v)
{
	const char *s = *p;
	int64_t x = 0;
	while (*p < end && **p >= '0' && **p <= '9') {
		int d = **p - '0';
		x = x > (NUM_MAX - d) / 10 ? NUM_MAX : x * 10 + d;
		(*p)++;
	}
	*v = x;
	return *p > s;
}

static int cmp(const void *a, const void *b)
{
	const bst_range *x = a, *y = b;
	return x->start < y->start ? -1 : x->start > y->start;
}

int bst_range_parse(bst_str hdr, off_t size, bst_range *out, int max, int *n)
{
	*n = 0;
	const char *p = hdr.p, *end = hdr.p + hdr.len;
	while (p < end && ows(*p))
		p++;
	if (end - p < 6 || strncasecmp(p, "bytes", 5) != 0 || p[5] != '=')
		return BST_RANGE_NONE;
	p += 6;
	int specs = 0, cnt = 0;
	for (;;) {
		while (p < end && (ows(*p) || *p == ','))
			p++;
		if (p >= end)
			break;
		if (++specs > max)
			return BST_RANGE_NONE; /* abuse: not worth honouring */
		int64_t first = 0, last = 0;
		bool has_first = num(&p, end, &first), has_last;
		if (p >= end || *p != '-')
			return BST_RANGE_NONE;
		p++;
		has_last = num(&p, end, &last);
		while (p < end && ows(*p))
			p++;
		if (p < end && *p != ',')
			return BST_RANGE_NONE;
		if (!has_first && !has_last)
			return BST_RANGE_NONE;
		bst_range r;
		if (!has_first) { /* the last `last` bytes */
			if (last == 0 || size == 0)
				continue;
			r.start = last >= size ? 0 : size - last;
			r.end = size - 1;
		} else {
			if (has_last && last < first)
				return BST_RANGE_NONE; /* syntactically invalid: ignore the header */
			if (first >= size)
				continue; /* unsatisfiable spec */
			r.start = first;
			r.end = !has_last || last >= size ? size - 1 : last;
		}
		out[cnt++] = r;
	}
	if (cnt == 0)
		return specs == 0 ? BST_RANGE_NONE : BST_RANGE_416;
	qsort(out, (size_t)cnt, sizeof *out, cmp);
	int w = 0;
	for (int i = 1; i < cnt; i++) {
		if (out[i].start <= out[w].end + 1) { /* overlaps or touches: end + 1 <= size, no overflow */
			if (out[i].end > out[w].end)
				out[w].end = out[i].end;
		} else {
			out[++w] = out[i];
		}
	}
	*n = w + 1;
	return BST_RANGE_OK;
}

bool bst_if_range_ok(bst_str v, bst_str etag, bool has_mtime, time_t mtime)
{
	const char *p = v.p, *end = v.p + v.len;
	while (p < end && ows(*p))
		p++;
	while (end > p && ows(end[-1]))
		end--;
	if (p == end)
		return false;
	if (*p == '"' || (end - p > 2 && p[0] == 'W' && p[1] == '/')) { /* an entity-tag */
		if (*p == 'W' || etag.len == 0 || etag.p[0] == 'W')
			return false; /* strong comparison only */
		return (size_t)(end - p) == etag.len && memcmp(p, etag.p, etag.len) == 0;
	}
	time_t d;
	if (!has_mtime || !bst_http_date_parse((bst_str){ p, (uint32_t)(end - p) }, &d))
		return false;
	return d == mtime;
}

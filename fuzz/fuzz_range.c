/* libFuzzer harness for Range parsing and If-Range. Properties: no crash or hang; with OK the
 * ranges lie inside [0, size), are ascending, neither overlap nor touch, number at most max and
 * together never exceed size; NONE and 416 leave n at 0. Input: 8 bytes of size, one byte of
 * max, then the header value. */
#include "handlers/range.h"
#include "http/conditional.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t len)
{
	if (len < 9)
		return 0;
	uint64_t raw;
	memcpy(&raw, d, 8);
	off_t size = (off_t)(raw >> 1); /* 0 .. INT64_MAX */
	int max = 1 + d[8] % 32;
	bst_str hdr = { (const char *)d + 9, (uint32_t)(len - 9 > 4096 ? 4096 : len - 9) };
	bst_range r[33];
	int n = -1;
	int st = bst_range_parse(hdr, size, r, max, &n);
	if (st != BST_RANGE_OK) {
		if (n != 0 || (st != BST_RANGE_NONE && st != BST_RANGE_416))
			abort();
	} else {
		if (n < 1 || n > max)
			abort();
		unsigned long long total = 0;
		for (int i = 0; i < n; i++) {
			if (r[i].start < 0 || r[i].end < r[i].start || r[i].end >= size)
				abort();
			if (i > 0 && r[i].start <= r[i - 1].end + 1)
				abort();
			total += (unsigned long long)(r[i].end - r[i].start) + 1;
		}
		if (total > (unsigned long long)size)
			abort();
	}
	(void)bst_if_range_ok(hdr, BST_S("\"a-b\""), true, (time_t)(raw >> 20));
	time_t t;
	(void)bst_http_date_parse(hdr, &t);
	return 0;
}

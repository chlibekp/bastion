/* libFuzzer harness for URI normalization. Properties: no crash; a successful result is an
 * absolute path with no "." or ".." segment, no NUL, and not longer than the input; merged
 * slashes leave no "//"; and normalize(encode(normalize(x))) is normalize(x). */
#include "route/uri.h"

#include <stdlib.h>
#include <string.h>

static void check(const char *p, size_t n, bool merge)
{
	if (n == 0 || p[0] != '/' || strlen(p) != n)
		abort();
	for (size_t i = 0; i < n; i++) {
		if (p[i] != '/')
			continue;
		size_t e = i + 1;
		while (e < n && p[e] != '/')
			e++;
		size_t len = e - i - 1;
		if ((len == 1 && p[i + 1] == '.') || (len == 2 && p[i + 1] == '.' && p[i + 2] == '.'))
			abort();
		if (merge && len == 0 && e < n)
			abort();
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size > 4096 || size == 0)
		return 0;
	static char out[4097 + 1], enc[3 * 4096 + 4], again[4097 + 1];
	for (unsigned fl = 0; fl < 4; fl++) {
		size_t n = 0;
		bool merge = fl & BST_URI_MERGE_SLASHES;
		if (bst_uri_normalize((bst_str){ (const char *)d, (uint32_t)size }, out, size + 1, fl, &n) != 0)
			continue;
		if (n > size)
			abort();
		check(out, n, merge);
		size_t en = 0, an = 0;
		if (bst_uri_encode_path((bst_str){ out, (uint32_t)n }, enc, sizeof enc, &en) != 0)
			abort();
		if (bst_uri_normalize((bst_str){ enc, (uint32_t)en }, again, sizeof again, fl, &an) != 0 &&
		    en <= sizeof again - 1)
			abort();
		else if (en <= sizeof again - 1 && (an != n || memcmp(again, out, n) != 0))
			abort(); /* not idempotent */
	}
	return 0;
}

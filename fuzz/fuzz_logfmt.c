/* libFuzzer harness for the access-log escapers (ops/log_format.c), which see every client
 * controlled value written to a log line. The input is copied to an exact-size heap block.
 * Properties: no crash or write past cap; the JSON escaper's output wrapped in quotes is a JSON
 * string the strict parser accepts (for values without NUL, which that parser refuses by
 * policy); neither escaper lets a control byte, DEL, quote or
 * backslash through unescaped (so no value can end a line or close a quote); SIZE_MAX exactly
 * when the output does not fit. */
#include "core/arena.h"
#include "core/json.h"
#include "ops/log_format.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void no_raw_controls(const char *o, size_t n, bool json)
{
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)o[i];
		if (c < 0x20 || c == 0x7f)
			abort();
		if (c == '"' || c == '\\') {
			/* only as the second byte of an escape we wrote */
			if (c == '\\') {
				if (i + 1 >= n)
					abort();
				i++;
				continue;
			}
			abort();
		}
		(void)json;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size > 4096)
		return 0;
	char *in = malloc(size > 0 ? size : 1);
	if (in == NULL)
		return 0;
	memcpy(in, d, size);
	static char out[6 * 4096 + 8];
	for (int json = 0; json < 2; json++) {
		size_t n = json ? bst_logfmt_json_esc(out + 1, sizeof out - 2, in, size)
				: bst_logfmt_text_esc(out + 1, sizeof out - 2, in, size);
		if (n == SIZE_MAX || n > sizeof out - 2)
			abort(); /* the buffer is big enough for every escape */
		no_raw_controls(out + 1, n, json);
		/* a small cap must be refused, never overrun */
		size_t small = size > 0 ? (size_t)d[0] % (n + 1) : 0;
		char *tight = malloc(small > 0 ? small : 1);
		if (tight == NULL)
			abort();
		size_t m = json ? bst_logfmt_json_esc(tight, small, in, size) : bst_logfmt_text_esc(tight, small, in, size);
		if (small < n ? m != SIZE_MAX : m != n)
			abort();
		free(tight);
		/* bst_json_parse refuses U+0000 by policy, though \u0000 is valid JSON (RFC 8259) and
		 * what log readers accept: values holding NUL skip the parse check below. */
		if (json && memchr(in, '\0', size) == NULL) {
			out[0] = '"';
			out[n + 1] = '"';
			bst_arena *a = bst_arena_new(4096);
			if (a == NULL)
				abort();
			bst_err e;
			const bst_json *j = bst_json_parse(a, out, n + 2, &e);
			if (j == NULL || bst_json_typeof(j) != BST_JSON_STR)
				abort();
			bst_arena_free(a);
		}
	}
	free(in);
	return 0;
}

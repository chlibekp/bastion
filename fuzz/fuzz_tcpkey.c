/* libFuzzer harness for the fastopen_key parser. The input is copied to an exact-size heap
 * block so ASan flags any read past len. Properties: only the two documented shapes (32 hex
 * digits, or four dash-separated groups of 8) are accepted, out is untouched on failure, and
 * an accepted key re-formats to the same bytes in both shapes. */
#include "io/tcp_profile.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size > 256)
		return 0;
	char *copy = malloc(size ? size : 1);
	if (!copy)
		abort();
	memcpy(copy, d, size);
	uint8_t out[BST_TCP_KEY_LEN], mark[BST_TCP_KEY_LEN];
	memset(out, 0xa5, sizeof out);
	memcpy(mark, out, sizeof out);
	if (bst_tcp_parse_key(copy, size, out)) {
		if (size != 32 && size != 35)
			abort();
		char plain[33], dashed[36];
		for (size_t i = 0; i < sizeof out; i++) {
			snprintf(plain + 2 * i, 3, "%02x", out[i]);
			snprintf(dashed + 2 * i + i / 4, 4, "%02x%s", out[i], i % 4 == 3 && i != 15 ? "-" : "");
		}
		uint8_t again[BST_TCP_KEY_LEN];
		if (!bst_tcp_parse_key(plain, 32, again) || memcmp(again, out, sizeof out) != 0)
			abort();
		if (!bst_tcp_parse_key(dashed, 35, again) || memcmp(again, out, sizeof out) != 0)
			abort();
	} else if (memcmp(out, mark, sizeof out) != 0) {
		abort(); /* a rejected key must not leave a half-written result */
	}
	free(copy);
	return 0;
}

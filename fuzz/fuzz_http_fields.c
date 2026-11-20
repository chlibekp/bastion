/* libFuzzer harness for small request field parsers not covered elsewhere: Accept-Encoding
 * negotiation (http/accept_encoding.c) and HTTP-date parsing (http/conditional.c). The input is
 * copied to an exact-size heap block. First byte: the allowed-coding mask.
 * Properties: no crash; the negotiated coding is identity or one of the allowed codings; an
 * absent field gives identity; a parsed date is not negative. */
#include "http/accept_encoding.h"
#include "http/conditional.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size < 1 || size > 4096)
		return 0;
	uint32_t allowed = d[0] & BST_ENC_ALL;
	size_t n = size - 1;
	char *buf = malloc(n > 0 ? n : 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, d + 1, n);
	bst_str v = { buf, (uint32_t)n };
	bst_encoding e = bst_negotiate_encoding(v, allowed);
	if (e >= BST_ENC_COUNT_ || (e != BST_ENC_IDENTITY && !(allowed & BST_ENC_BIT(e))))
		abort();
	if (bst_negotiate_encoding((bst_str){ NULL, 0 }, allowed) != BST_ENC_IDENTITY)
		abort();
	if (bst_encoding_name(e).len == 0)
		abort();
	time_t t = -1;
	if (bst_http_date_parse(v, &t) && t < 0)
		abort();
	free(buf);
	return 0;
}

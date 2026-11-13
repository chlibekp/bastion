/* libFuzzer harness for the PROXY protocol parser (src/proxy/proxyproto.c). The input is copied
 * to an exact-size heap block so ASan flags any read past len. Properties: a complete header is
 * never longer than the input or BST_PP_MAX; reading it the way the accept side does
 * (bst_pp_want, then bst_pp_parse on the prefix) reaches the same result without reading past
 * the header; a header with addresses written back by either writer parses to the same ones. */
#include "proxy/proxyproto.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size > 2 * BST_PP_MAX)
		return 0;
	uint8_t *copy = malloc(size ? size : 1);
	if (!copy)
		abort();
	memcpy(copy, d, size);
	bst_pp_info i;
	int rc = bst_pp_parse(copy, size, &i);
	if (rc > 0 && ((size_t)rc > size || (size_t)rc > BST_PP_MAX || i.len != (size_t)rc))
		abort();

	size_t n = 0;
	int inc = 0;
	while (inc == 0 && n < size) {
		size_t w = bst_pp_want(copy, n);
		if (w == 0)
			abort();
		n = n + w > size ? size : n + w;
		inc = bst_pp_parse(copy, n, &i);
	}
	if (rc > 0 && inc != rc)
		abort(); /* byte-exact reading finds the same header */
	if (inc > 0 && (size_t)inc != n)
		abort(); /* and never reads past it */

	if (rc > 0 && i.has_addr) {
		bst_pp_info back;
		char b1[BST_PP_V1_MAX + 1];
		uint8_t b2[BST_PP_V2_OUT_MAX];
		size_t l1 = bst_pp_write_v1(&i.src, &i.dst, b1, sizeof b1);
		size_t l2 = bst_pp_write_v2(&i.src, &i.dst, b2, sizeof b2);
		if (l1 == 0 || bst_pp_parse((const uint8_t *)b1, l1, &back) != (int)l1 || !back.has_addr ||
		    back.src.port != i.src.port || back.dst.port != i.dst.port)
			abort();
		if (l2 == 0 || bst_pp_parse(b2, l2, &back) != (int)l2)
			abort();
		bst_ip a = bst_ip_canon(&back.src.ip), b = bst_ip_canon(&i.src.ip);
		bst_ip c = bst_ip_canon(&back.dst.ip), e = bst_ip_canon(&i.dst.ip);
		if (!bst_ip_eq(&a, &b) || !bst_ip_eq(&c, &e)) /* a v4-mapped address may come back as v4 */
			abort();
	}
	free(copy);
	return 0;
}

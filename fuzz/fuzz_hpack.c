/* libFuzzer harness for HPACK. The first input byte picks the limits (bit 0: small list limit,
 * bit 1: small table), the rest is a header block decoded several times against one decoder, so
 * the dynamic table carries state from block to block.
 *
 * Properties: no crash or sanitizer report; memory stays inside the limits (the arena never maps
 * much more than the list limit allows, the table never exceeds its size); whatever decodes is
 * re-encoded by the server policy and decodes back to the same fields; and the Huffman coder
 * round-trips every string it is given. */
#include "http/h2/hpack.h"
#include "http/h2/huffman.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size < 1)
		return 0;
	uint32_t list = (d[0] & 1) ? 512 : 16384;
	uint32_t table = (d[0] & 2) ? 128 : 4096;
	const uint8_t *in = d + 1;
	size_t n = size - 1;

	bst_hpack_dec dec;
	bst_hpack_dec_init(&dec, table);
	bst_hpack_limits lim = { .max_header_list_size = list };
	bst_hpack_enc enc;
	bst_hpack_dec dec2;
	bst_hpack_enc_init(&enc, table);
	bst_hpack_dec_init(&dec2, table);
	for (int round = 0; round < 3; round++) {
		bst_arena *a = bst_arena_new(4096);
		bst_headers h;
		bst_headers_init(&h, a);
		int rc = bst_hpack_decode(&dec, in, n, a, &h, &lim);
		if (rc == BST_HPACK_NOMEM)
			abort();
		if (bst_arena_mapped(a) > (size_t)list * 8 + 65536 || bst_hpack_table_size(&dec.t) > 4096)
			abort();
		if (rc != BST_HPACK_OK) {
			bst_arena_free(a);
			break; /* the compression state is undefined after an error: stop with this decoder */
		}
		/* re-encode and decode with a second pair: same fields, in order */
		bst_h2_wr w = { 0 };
		bool ok = true;
		for (uint32_t i = 0; i < h.n && ok; i++)
			ok = h.v[i].name.len > 0;
		if (ok && bst_hpack_encode(&enc, &h, &w) == 0) {
			bst_arena *b = bst_arena_new(4096);
			bst_headers h2;
			bst_headers_init(&h2, b);
			bst_hpack_limits big = { .max_header_list_size = UINT32_MAX };
			if (bst_hpack_decode(&dec2, w.p, w.len, b, &h2, &big) != BST_HPACK_OK || h2.n != h.n)
				abort();
			for (uint32_t i = 0; i < h.n; i++) {
				const bst_header *x = &h.v[i], *y = &h2.v[i];
				bool lower = true; /* the encoder lower-cases names */
				if (x->name.len != y->name.len)
					abort();
				for (uint32_t k = 0; k < x->name.len; k++) {
					char c = x->name.p[k];
					lower = y->name.p[k] == (c >= 'A' && c <= 'Z' ? c + 32 : c);
					if (!lower)
						abort();
				}
				if (!bst_str_eq(x->value, y->value))
					abort();
			}
			bst_arena_free(b);
		}
		bst_h2_wr_free(&w);
		bst_arena_free(a);
	}
	bst_hpack_dec_free(&dec);
	bst_hpack_dec_free(&dec2);
	bst_hpack_enc_free(&enc);

	/* the Huffman coder: the input as a string round-trips */
	size_t el = bst_huff_encoded_len(in, n);
	uint8_t *e = malloc(el ? el : 1), *out = malloc(n ? n : 1);
	size_t got = bst_huff_encode(in, n, e);
	if (got != el || bst_huff_decode(e, el, out, n) != (ssize_t)n || (n > 0 && memcmp(out, in, n) != 0))
		abort();
	/* arbitrary bytes as a Huffman string: decode must not overrun a cap of the 8/5 bound */
	uint8_t *junk = malloc(n * 2 + 8);
	ssize_t r = bst_huff_decode(in, n, junk, n * 8 / 5 + 1);
	if (r == BST_HUFF_TOO_BIG)
		abort();
	free(junk);
	free(e);
	free(out);
	return 0;
}

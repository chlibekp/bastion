#include "http/h2/huffman.h"

#include <stdbool.h>

#include "http/h2/huffman_table.inc"

size_t bst_huff_encoded_len(const uint8_t *s, size_t n)
{
	uint64_t bits = 0;
	for (size_t i = 0; i < n; i++)
		bits += hpack_huff_enc[s[i]].len;
	return (size_t)((bits + 7) / 8);
}

size_t bst_huff_encode(const uint8_t *s, size_t n, uint8_t *out)
{
	uint64_t acc = 0; /* bits not yet written sit in the low `have` bits */
	unsigned have = 0;
	size_t o = 0;
	for (size_t i = 0; i < n; i++) {
		acc = acc << hpack_huff_enc[s[i]].len | hpack_huff_enc[s[i]].code;
		have += hpack_huff_enc[s[i]].len;
		while (have >= 8) {
			have -= 8;
			out[o++] = (uint8_t)(acc >> have);
		}
	}
	if (have > 0) /* pad with the high bits of EOS: all ones */
		out[o++] = (uint8_t)(acc << (8 - have) | (0xffu >> have));
	return o;
}

ssize_t bst_huff_decode(const uint8_t *in, size_t n, uint8_t *out, size_t cap)
{
	unsigned st = 0;
	size_t o = 0;
	for (size_t i = 0; i < n; i++) {
		for (int half = 0; half < 2; half++) {
			unsigned nib = half == 0 ? in[i] >> 4 : in[i] & 0xf;
			__typeof__(hpack_huff_dec[0][0]) e = hpack_huff_dec[st][nib];
			if (e.flags & 2)
				return BST_HUFF_ERR;
			if (e.flags & 1) {
				if (o >= cap)
					return BST_HUFF_TOO_BIG;
				out[o++] = e.sym;
			}
			st = e.next;
		}
	}
	return hpack_huff_accept[st] ? (ssize_t)o : BST_HUFF_ERR;
}

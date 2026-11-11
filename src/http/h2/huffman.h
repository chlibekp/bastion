/* The HPACK Huffman code (RFC 7541 Appendix B and section 5.2). The tables are generated
 * (scripts/gen-huffman.py); the decoder reads the input a nibble at a time. */
#ifndef BST_HTTP_H2_HUFFMAN_H
#define BST_HTTP_H2_HUFFMAN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* The encoded length in bytes of s[0..n), padding included. */
size_t bst_huff_encoded_len(const uint8_t *s, size_t n);
/* Writes the encoding of s into out, which must have bst_huff_encoded_len(s, n) bytes; returns
 * that length. The padding is the most significant bits of EOS (ones). */
size_t bst_huff_encode(const uint8_t *s, size_t n, uint8_t *out);

#define BST_HUFF_ERR (-1)      /* invalid: EOS in the data, padding over 7 bits or not all ones */
#define BST_HUFF_TOO_BIG (-2)  /* the output would not fit in cap */
/* Decodes in[0..n) into out (cap bytes). Returns the decoded length, or BST_HUFF_ERR or
 * BST_HUFF_TOO_BIG. A code is at least 5 bits, so n bytes decode to at most n * 8 / 5. */
ssize_t bst_huff_decode(const uint8_t *in, size_t n, uint8_t *out, size_t cap);

#endif

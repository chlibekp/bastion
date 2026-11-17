/* Base64 (RFC 4648 section 4) and base64url (section 5), strict: no whitespace, no characters
 * outside the alphabet, padding only where the flags allow it, and non-zero trailing bits
 * rejected so every byte string has one encoding. */
#ifndef BST_CORE_B64_H
#define BST_CORE_B64_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum bst_b64_flags {
	BST_B64_STD = 0,	   /* + and / */
	BST_B64_URL = 1,	   /* - and _ */
	BST_B64_PAD_OPTIONAL = 2,  /* "=" padding accepted (and then required to be right) */
	BST_B64_PAD_FORBIDDEN = 4, /* any "=" is an error */
} bst_b64_flags;

/* Decoded length, or -1 on any error or when the result would not fit cap. */
long bst_b64_decode(const char *in, size_t len, uint8_t *out, size_t cap, int flags);
/* Encodes without padding (with when pad); NUL-terminates. The length, or 0 when cap is short. */
size_t bst_b64_encode(const uint8_t *in, size_t len, char *out, size_t cap, int flags, bool pad);

#endif

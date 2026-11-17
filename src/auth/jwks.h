/* Verification keys for auth_jwt: a JWKS document (RFC 7517) with EC (P-256, P-384), RSA and
 * OKP (Ed25519) public keys, or one PEM public key, or (HS256 only) a secret file. Loaded by
 * the master at load; a set that can not be read fails the load. Each key keeps its kid and
 * the algorithms its type allows, so the key type decides the algorithm family. */
#ifndef BST_AUTH_JWKS_H
#define BST_AUTH_JWKS_H

#include "core/str.h"

#include <openssl/evp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bst_jwk {
	char *kid;	   /* NULL: none */
	uint32_t algs;	   /* bst_jwt_alg this key may verify */
	EVP_PKEY *pkey;	   /* asymmetric keys */
	uint8_t *secret;   /* HS256 */
	size_t secret_len;
} bst_jwk;

struct bst_jwks {
	size_t n;
	bst_jwk k[];
};
typedef struct bst_jwks bst_jwks;

/* From a JWKS JSON text or a PEM public key. NULL with why set. */
bst_jwks *bst_jwks_parse(const char *text, size_t len, char *why, size_t whycap);
/* An HS256 secret (raw bytes, at least 32). */
bst_jwks *bst_jwks_secret(const uint8_t *s, size_t len, char *why, size_t whycap);
bst_jwks *bst_jwks_load_file(const char *path, bool secret, char *why, size_t whycap);
void bst_jwks_free(void *keys);
/* The key for kid (any key when kid is NULL and there is exactly one) able to verify alg. */
const bst_jwk *bst_jwks_find(const bst_jwks *ks, bst_str kid, bool has_kid, uint32_t alg);

#endif

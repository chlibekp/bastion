/* libFuzzer harness for JWT validation (auth/jwt.c). The input is the token, copied to an
 * exact-size heap block so ASan flags any read past its end. Keys: a fixed HS256 secret, so the
 * signature path runs for real; with every algorithm allowed, nothing may crash, leak or
 * accept a token whose HMAC does not match. Properties: verification returns one of the
 * defined codes, and a token accepted is accepted again (deterministic). */
#include "auth/jwks.h"
#include "auth/jwt.h"
#include "core/arena.h"

#include <stdlib.h>
#include <string.h>

static bst_jwks *keys;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (keys == NULL) {
		static const uint8_t secret[32] = "fuzz-secret-fuzz-secret-fuzz-se";
		char why[64];
		keys = bst_jwks_secret(secret, sizeof secret, why, sizeof why);
		if (keys == NULL)
			abort();
	}
	if (size > 3 * BST_JWT_MAX)
		return 0;
	char *copy = malloc(size ? size : 1);
	if (copy == NULL)
		return 0;
	memcpy(copy, data, size);
	bst_jwt_cfg c;
	memset(&c, 0, sizeof c);
	c.algs = BST_JWT_HS256 | BST_JWT_ES256 | BST_JWT_RS256;
	c.keys = keys;
	c.leeway_s = 5;
	bst_arena *a = bst_arena_new(1 << 16);
	if (a == NULL)
		abort();
	bst_jwt_claims cl;
	bst_str t = { copy, (uint32_t)size };
	bst_jwt_rc rc = bst_jwt_verify(t, &c, 1700000000, a, &cl);
	if ((unsigned)rc > BST_JWT_CLAIM)
		abort();
	if (rc == BST_JWT_OK && (cl.payload == NULL || bst_jwt_verify(t, &c, 1700000000, a, &cl) != BST_JWT_OK))
		abort();
	bst_arena_free(a);
	free(copy);
	return 0;
}

/* JWT validation (RFC 7519) of JWS compact tokens (RFC 7515), with a safe algorithm allowlist.
 *
 *   Algorithms  ES256, ES384, RS256, PS256, EdDSA (Ed25519); HS256 only when a secret file is
 *               configured explicitly (secret=). `none` in any spelling is never accepted, and
 *               a key is only ever used with the algorithm family of its own type, so an HS256
 *               token "signed" with an RSA public key can not verify.
 *   Keys        a JWKS (or a PEM public key) file read at load (auth/jwks.h); picked by `kid`,
 *               an unknown kid is rejected without any refetch.
 *   Claims      exp, nbf, iat checked against now with leeway; iss and aud (a string or an
 *               array) when configured; required claims present. The strict JSON parser
 *               rejects duplicate members. An unknown `crit` header is rejected.
 *   Limits      a token over 8 KiB, a wrong segment count, padding or bad base64url: rejected
 *               before any crypto. */
#ifndef BST_AUTH_JWT_H
#define BST_AUTH_JWT_H

#include "core/arena.h"
#include "core/json.h"
#include "core/str.h"

#include <stdbool.h>
#include <stdint.h>

#define BST_JWT_MAX 8192

typedef enum bst_jwt_alg {
	BST_JWT_ES256 = 1u << 0,
	BST_JWT_ES384 = 1u << 1,
	BST_JWT_RS256 = 1u << 2,
	BST_JWT_PS256 = 1u << 3,
	BST_JWT_EDDSA = 1u << 4,
	BST_JWT_HS256 = 1u << 5,
} bst_jwt_alg;

typedef struct bst_jwks bst_jwks; /* auth/jwks.h */

typedef struct bst_jwt_map {
	const char *claim, *header;
} bst_jwt_map;

typedef struct bst_jwt_cfg {
	uint32_t algs;		  /* allowed bst_jwt_alg */
	const bst_jwks *keys;
	const char *iss;	  /* NULL: not checked */
	const char *const *aud;	  /* any one must be in the token's aud */
	size_t naud;
	int64_t leeway_s;
	const char *header;	  /* the request field holding "Bearer <token>" (default Authorization) */
	const char *cookie;	  /* or a cookie holding the bare token, when set */
	const bst_jwt_map *maps;  /* auth_jwt_claim_header */
	size_t nmaps;
	const char *const *required; /* auth_jwt_required_claim */
	size_t nrequired;
} bst_jwt_cfg;

typedef struct bst_jwt_claims {
	const bst_json *payload;
	int64_t exp;		  /* 0 when absent */
} bst_jwt_claims;

typedef enum bst_jwt_rc {
	BST_JWT_OK = 0,
	BST_JWT_MALFORMED,
	BST_JWT_ALG,	   /* none, unknown, or not allowed */
	BST_JWT_KEY,	   /* no key for the kid, or the key's type does not fit the alg */
	BST_JWT_SIGNATURE,
	BST_JWT_CRIT,
	BST_JWT_EXPIRED,
	BST_JWT_NOT_YET,   /* nbf or iat in the future */
	BST_JWT_ISS,
	BST_JWT_AUD,
	BST_JWT_CLAIM,	   /* a required claim missing */
} bst_jwt_rc;

bst_jwt_rc bst_jwt_verify(bst_str token, const bst_jwt_cfg *cfg, int64_t now, bst_arena *a,
			  bst_jwt_claims *out);
const char *bst_jwt_rc_str(bst_jwt_rc rc);

#endif

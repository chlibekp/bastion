/* See jwks.h. */
#include "auth/jwks.h"

#include "auth/jwt.h"
#include "core/arena.h"
#include "core/b64.h"
#include "core/json.h"

#include <errno.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEYS_MAX 64
#define FILE_MAX (1u << 20)

static bool str_of(const bst_json *o, const char *k, bst_str *out)
{
	const bst_json *v = o ? bst_json_get(o, k) : NULL;
	return v != NULL && bst_json_str(v, out);
}

static long b64url(bst_str s, uint8_t *out, size_t cap)
{
	return bst_b64_decode(s.p, s.len, out, cap, BST_B64_URL | BST_B64_PAD_FORBIDDEN);
}

static uint32_t algs_of_pkey(EVP_PKEY *k)
{
	if (EVP_PKEY_is_a(k, "RSA"))
		return EVP_PKEY_get_bits(k) >= 2048 ? (BST_JWT_RS256 | BST_JWT_PS256) : 0;
	if (EVP_PKEY_is_a(k, "ED25519"))
		return BST_JWT_EDDSA;
	if (EVP_PKEY_is_a(k, "EC")) {
		char g[64];
		size_t gl = 0;
		if (EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_GROUP_NAME, g, sizeof g, &gl) != 1)
			return 0;
		if (strcmp(g, "prime256v1") == 0 || strcmp(g, "P-256") == 0)
			return BST_JWT_ES256;
		if (strcmp(g, "secp384r1") == 0 || strcmp(g, "P-384") == 0)
			return BST_JWT_ES384;
	}
	return 0;
}

static uint32_t alg_bit(bst_str a)
{
	static const struct { const char *n; uint32_t b; } t[] = {
		{ "ES256", BST_JWT_ES256 }, { "ES384", BST_JWT_ES384 }, { "RS256", BST_JWT_RS256 },
		{ "PS256", BST_JWT_PS256 }, { "EdDSA", BST_JWT_EDDSA }, { "HS256", BST_JWT_HS256 },
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
		if (bst_str_eq(a, (bst_str){ t[i].n, (uint32_t)strlen(t[i].n) }))
			return t[i].b;
	return 0;
}

static EVP_PKEY *from_params(const char *type, OSSL_PARAM_BLD *b)
{
	OSSL_PARAM *ps = OSSL_PARAM_BLD_to_param(b);
	EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
	EVP_PKEY *k = NULL;
	if (ps == NULL || pc == NULL || EVP_PKEY_fromdata_init(pc) != 1 ||
	    EVP_PKEY_fromdata(pc, &k, EVP_PKEY_PUBLIC_KEY, ps) != 1)
		k = NULL;
	EVP_PKEY_CTX_free(pc);
	OSSL_PARAM_free(ps);
	return k;
}

static EVP_PKEY *jwk_rsa(const bst_json *o)
{
	bst_str n, e;
	uint8_t nb[1024], eb[16];
	long nl, el;
	if (!str_of(o, "n", &n) || !str_of(o, "e", &e) || (nl = b64url(n, nb, sizeof nb)) <= 0 ||
	    (el = b64url(e, eb, sizeof eb)) <= 0)
		return NULL;
	BIGNUM *bn = BN_bin2bn(nb, (int)nl, NULL), *be = BN_bin2bn(eb, (int)el, NULL);
	OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
	EVP_PKEY *k = NULL;
	if (bn && be && b && OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_RSA_N, bn) == 1 &&
	    OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_RSA_E, be) == 1)
		k = from_params("RSA", b);
	OSSL_PARAM_BLD_free(b);
	BN_free(bn);
	BN_free(be);
	return k;
}

static EVP_PKEY *jwk_ec(const bst_json *o)
{
	bst_str crv, x, y;
	if (!str_of(o, "crv", &crv) || !str_of(o, "x", &x) || !str_of(o, "y", &y))
		return NULL;
	size_t cl;
	const char *group;
	if (bst_str_eq(crv, BST_S("P-256"))) {
		cl = 32;
		group = "prime256v1";
	} else if (bst_str_eq(crv, BST_S("P-384"))) {
		cl = 48;
		group = "secp384r1";
	} else {
		return NULL;
	}
	uint8_t pt[1 + 2 * 48];
	pt[0] = 0x04;
	if (b64url(x, pt + 1, cl) != (long)cl || b64url(y, pt + 1 + cl, cl) != (long)cl)
		return NULL;
	OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
	EVP_PKEY *k = NULL;
	if (b && OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, group, 0) == 1 &&
	    OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PUB_KEY, pt, 1 + 2 * cl) == 1)
		k = from_params("EC", b);
	OSSL_PARAM_BLD_free(b);
	return k;
}

static EVP_PKEY *jwk_okp(const bst_json *o)
{
	bst_str crv, x;
	uint8_t xb[32];
	if (!str_of(o, "crv", &crv) || !bst_str_eq(crv, BST_S("Ed25519")) || !str_of(o, "x", &x) ||
	    b64url(x, xb, sizeof xb) != 32)
		return NULL;
	return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, xb, 32);
}

static bst_jwks *alloc_set(size_t n)
{
	return calloc(1, sizeof(bst_jwks) + n * sizeof(bst_jwk));
}

void bst_jwks_free(void *p)
{
	bst_jwks *ks = p;
	if (ks == NULL)
		return;
	for (size_t i = 0; i < ks->n; i++) {
		free(ks->k[i].kid);
		EVP_PKEY_free(ks->k[i].pkey);
		if (ks->k[i].secret != NULL) {
			OPENSSL_cleanse(ks->k[i].secret, ks->k[i].secret_len);
			free(ks->k[i].secret);
		}
	}
	free(ks);
}

static bst_jwks *from_pem(const char *text, size_t len, char *why, size_t whycap)
{
	BIO *bio = BIO_new_mem_buf(text, (int)len);
	EVP_PKEY *k = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
	BIO_free(bio);
	uint32_t algs = k ? algs_of_pkey(k) : 0;
	bst_jwks *ks = algs ? alloc_set(1) : NULL;
	if (ks == NULL) {
		EVP_PKEY_free(k);
		snprintf(why, whycap, "not a usable PEM public key (RSA >= 2048, P-256, P-384, Ed25519)");
		return NULL;
	}
	ks->n = 1;
	ks->k[0].pkey = k;
	ks->k[0].algs = algs;
	return ks;
}

bst_jwks *bst_jwks_parse(const char *text, size_t len, char *why, size_t whycap)
{
	if (len >= 10 && memcmp(text, "-----BEGIN", 10) == 0)
		return from_pem(text, len, why, whycap);
	bst_arena *a = bst_arena_new(64 << 10);
	if (a == NULL) {
		snprintf(why, whycap, "out of memory");
		return NULL;
	}
	bst_err e = { .msg = "" };
	const bst_json *doc = bst_json_parse(a, text, len, &e);
	const bst_json *keys = doc ? bst_json_get(doc, "keys") : NULL;
	size_t n = keys && bst_json_typeof(keys) == BST_JSON_ARR ? bst_json_arr_len(keys) : 0;
	bst_jwks *ks = NULL;
	if (doc == NULL) {
		snprintf(why, whycap, "not JSON: %s", e.msg);
		goto out;
	}
	if (keys == NULL || bst_json_typeof(keys) != BST_JSON_ARR || n > KEYS_MAX) {
		snprintf(why, whycap, "no \"keys\" array of at most %u keys", KEYS_MAX);
		goto out;
	}
	ks = alloc_set(n);
	if (ks == NULL) {
		snprintf(why, whycap, "out of memory");
		goto out;
	}
	for (size_t i = 0; i < n; i++) {
		const bst_json *o = bst_json_arr_at(keys, i);
		bst_str kty, use, kid, alg;
		if (!str_of(o, "kty", &kty))
			continue;
		if (str_of(o, "use", &use) && !bst_str_eq(use, BST_S("sig")))
			continue; /* an encryption key never verifies */
		EVP_PKEY *k = bst_str_eq(kty, BST_S("RSA")) ? jwk_rsa(o)
			      : bst_str_eq(kty, BST_S("EC")) ? jwk_ec(o)
			      : bst_str_eq(kty, BST_S("OKP")) ? jwk_okp(o)
								: NULL;
		uint32_t algs = k ? algs_of_pkey(k) : 0;
		if (algs != 0 && str_of(o, "alg", &alg))
			algs &= alg_bit(alg); /* the key's own alg narrows it */
		if (algs == 0) {
			EVP_PKEY_free(k);
			continue; /* unusable keys are skipped, not fatal: a JWKS may hold others */
		}
		bst_jwk *j = &ks->k[ks->n++];
		j->pkey = k;
		j->algs = algs;
		if (str_of(o, "kid", &kid)) {
			j->kid = strndup(kid.p, kid.len);
			if (j->kid == NULL) {
				bst_jwks_free(ks);
				ks = NULL;
				snprintf(why, whycap, "out of memory");
				goto out;
			}
		}
	}
out:
	bst_arena_free(a);
	return ks;
}

bst_jwks *bst_jwks_secret(const uint8_t *s, size_t len, char *why, size_t whycap)
{
	if (len < 32) {
		snprintf(why, whycap, "an HS256 secret needs at least 32 bytes");
		return NULL;
	}
	bst_jwks *ks = alloc_set(1);
	uint8_t *c = malloc(len);
	if (ks == NULL || c == NULL) {
		free(ks);
		free(c);
		snprintf(why, whycap, "out of memory");
		return NULL;
	}
	memcpy(c, s, len);
	ks->n = 1;
	ks->k[0].secret = c;
	ks->k[0].secret_len = len;
	ks->k[0].algs = BST_JWT_HS256;
	return ks;
}

bst_jwks *bst_jwks_load_file(const char *path, bool secret, char *why, size_t whycap)
{
	FILE *f = fopen(path, "re");
	if (f == NULL) {
		snprintf(why, whycap, "%s", strerror(errno));
		return NULL;
	}
	char *buf = malloc(FILE_MAX);
	size_t n = buf ? fread(buf, 1, FILE_MAX, f) : 0;
	bool big = buf && n == FILE_MAX;
	fclose(f);
	bst_jwks *ks = NULL;
	if (buf == NULL)
		snprintf(why, whycap, "out of memory");
	else if (big)
		snprintf(why, whycap, "larger than 1 MiB");
	else if (secret) {
		while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
			n--;
		ks = bst_jwks_secret((const uint8_t *)buf, n, why, whycap);
	} else {
		ks = bst_jwks_parse(buf, n, why, whycap);
		if (ks != NULL && ks->n == 0) {
			bst_jwks_free(ks);
			ks = NULL;
			snprintf(why, whycap, "no usable signing key");
		}
	}
	if (buf != NULL) {
		OPENSSL_cleanse(buf, n);
		free(buf);
	}
	return ks;
}

const bst_jwk *bst_jwks_find(const bst_jwks *ks, bst_str kid, bool has_kid, uint32_t alg)
{
	if (ks == NULL)
		return NULL;
	const bst_jwk *only = NULL;
	size_t fits = 0;
	for (size_t i = 0; i < ks->n; i++) {
		const bst_jwk *k = &ks->k[i];
		if ((k->algs & alg) == 0)
			continue;
		if (has_kid) {
			if (k->kid != NULL && strlen(k->kid) == kid.len && memcmp(k->kid, kid.p, kid.len) == 0)
				return k;
			continue;
		}
		only = k;
		fits++;
	}
	return !has_kid && fits == 1 ? only : NULL; /* no kid: only when unambiguous */
}

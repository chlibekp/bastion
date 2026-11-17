#include "auth/jwks.h"
#include "auth/jwt.h"
#include "core/b64.h"
#include "tap.h"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>

#define NOW 1700000000

static EVP_PKEY *ec_key, *rsa_key, *ed_key;
static bst_jwks *keys;
static char rsa_pem[4096];

static void b64u(const void *in, size_t n, char *out, size_t cap)
{
	bst_b64_encode(in, n, out, cap, BST_B64_URL, false);
}

/* header.payload.signature with key k and alg; sig_override replaces the signature segment. */
static void sign(char *out, size_t cap, const char *hdr, const char *pay, EVP_PKEY *k,
		 const char *alg)
{
	char h[1024], p[2048];
	b64u(hdr, strlen(hdr), h, sizeof h);
	b64u(pay, strlen(pay), p, sizeof p);
	char in[4096];
	snprintf(in, sizeof in, "%s.%s", h, p);
	uint8_t sig[1024];
	size_t sl = sizeof sig;
	if (strcmp(alg, "HS256") == 0) {
		const uint8_t *secret = (const uint8_t *)rsa_pem; /* the RSA public key as HMAC key */
		size_t ml = 0;
		EVP_MAC *m = EVP_MAC_fetch(NULL, "HMAC", NULL);
		EVP_MAC_CTX *mc = EVP_MAC_CTX_new(m);
		OSSL_PARAM ps[] = { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
				    OSSL_PARAM_construct_end() };
		EVP_MAC_init(mc, secret, strlen(rsa_pem), ps);
		EVP_MAC_update(mc, (uint8_t *)in, strlen(in));
		EVP_MAC_final(mc, sig, &ml, sizeof sig);
		EVP_MAC_CTX_free(mc);
		EVP_MAC_free(m);
		sl = ml;
	} else {
		EVP_MD_CTX *mc = EVP_MD_CTX_new();
		EVP_PKEY_CTX *pc = NULL;
		const char *md = strcmp(alg, "EdDSA") == 0 ? NULL : strcmp(alg, "ES384") == 0 ? "SHA384" : "SHA256";
		EVP_DigestSignInit_ex(mc, &pc, md, NULL, NULL, k, NULL);
		if (strcmp(alg, "PS256") == 0) {
			EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING);
			EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST);
		}
		EVP_DigestSign(mc, sig, &sl, (uint8_t *)in, strlen(in));
		EVP_MD_CTX_free(mc);
		if (strncmp(alg, "ES", 2) == 0) { /* DER to r||s */
			const uint8_t *q = sig;
			ECDSA_SIG *es = d2i_ECDSA_SIG(NULL, &q, (long)sl);
			const BIGNUM *r, *s;
			ECDSA_SIG_get0(es, &r, &s);
			uint8_t raw[64];
			BN_bn2binpad(r, raw, 32);
			BN_bn2binpad(s, raw + 32, 32);
			ECDSA_SIG_free(es);
			memcpy(sig, raw, 64);
			sl = 64;
		}
	}
	char s64[2048];
	b64u(sig, sl, s64, sizeof s64);
	snprintf(out, cap, "%s.%s", in, s64);
}

static bst_jwt_rc verify(const char *tok, const bst_jwt_cfg *c, int64_t now)
{
	bst_arena *a = bst_arena_new(1 << 16);
	bst_jwt_claims cl;
	bst_jwt_rc rc = bst_jwt_verify((bst_str){ tok, (uint32_t)strlen(tok) }, c, now, a, &cl);
	bst_arena_free(a);
	return rc;
}

static void jwk_coord(EVP_PKEY *k, const char *param, char *out, size_t cap)
{
	BIGNUM *b = NULL;
	EVP_PKEY_get_bn_param(k, param, &b);
	uint8_t raw[512];
	int n = BN_bn2bin(b, raw);
	if (strcmp(param, OSSL_PKEY_PARAM_EC_PUB_X) == 0 || strcmp(param, OSSL_PKEY_PARAM_EC_PUB_Y) == 0)
		n = BN_bn2binpad(b, raw, 32);
	b64u(raw, (size_t)n, out, cap);
	BN_free(b);
}

static void setup(void)
{
	ec_key = EVP_EC_gen("P-256");
	rsa_key = EVP_RSA_gen(2048);
	ed_key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
	char x[64], y[64], n[512], e[16], ex[64];
	jwk_coord(ec_key, OSSL_PKEY_PARAM_EC_PUB_X, x, sizeof x);
	jwk_coord(ec_key, OSSL_PKEY_PARAM_EC_PUB_Y, y, sizeof y);
	jwk_coord(rsa_key, OSSL_PKEY_PARAM_RSA_N, n, sizeof n);
	jwk_coord(rsa_key, OSSL_PKEY_PARAM_RSA_E, e, sizeof e);
	uint8_t raw[32];
	size_t rl = sizeof raw;
	EVP_PKEY_get_raw_public_key(ed_key, raw, &rl);
	b64u(raw, rl, ex, sizeof ex);
	char doc[2048];
	snprintf(doc, sizeof doc,
		 "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"ec1\",\"x\":\"%s\",\"y\":\"%s\"},"
		 "{\"kty\":\"RSA\",\"kid\":\"rsa1\",\"n\":\"%s\",\"e\":\"%s\"},"
		 "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"ed1\",\"x\":\"%s\"}]}", x, y, n, e, ex);
	char why[160];
	keys = bst_jwks_parse(doc, strlen(doc), why, sizeof why);
	BIO *b = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(b, rsa_key);
	int l = BIO_read(b, rsa_pem, sizeof rsa_pem - 1);
	rsa_pem[l > 0 ? l : 0] = '\0';
	BIO_free(b);
}

static bst_jwt_cfg cfg(void)
{
	bst_jwt_cfg c;
	memset(&c, 0, sizeof c);
	c.algs = BST_JWT_ES256 | BST_JWT_RS256 | BST_JWT_PS256 | BST_JWT_EDDSA;
	c.keys = keys;
	return c;
}

#define PAY "{\"sub\":\"u1\",\"exp\":1700000100}"

TEST(keys_loaded)
{
	setup();
	ASSERT(keys != NULL);
	ASSERT_EQ(keys->n, 3u);
}

TEST(rfc_shapes)
{
	/* every allowed algorithm round-trips (RFC 7515 compact form, RFC 7518 JOSE ECDSA) */
	bst_jwt_cfg c = cfg();
	char t[4096];
	sign(t, sizeof t, "{\"alg\":\"ES256\",\"kid\":\"ec1\"}", PAY, ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_OK);
	sign(t, sizeof t, "{\"alg\":\"RS256\",\"kid\":\"rsa1\"}", PAY, rsa_key, "RS256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_OK);
	sign(t, sizeof t, "{\"alg\":\"PS256\",\"kid\":\"rsa1\"}", PAY, rsa_key, "PS256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_OK);
	sign(t, sizeof t, "{\"alg\":\"EdDSA\",\"kid\":\"ed1\"}", PAY, ed_key, "EdDSA");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_OK);
	/* RFC 7519 section 3.1 example token (HS256, its JWK secret): verifies with that key */
	static const uint8_t k[] = { 3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
		143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90,
		146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8,
		192, 205, 154, 245, 103, 208, 128, 163 };
	char why[64];
	bst_jwks *hk = bst_jwks_secret(k, sizeof k, why, sizeof why);
	bst_jwt_cfg h = cfg();
	h.algs = BST_JWT_HS256;
	h.keys = hk;
	const char *rfc = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
			  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
			  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	ASSERT_EQ(verify(rfc, &h, 1300819370), BST_JWT_OK);
	ASSERT_EQ(verify(rfc, &h, 1300819381), BST_JWT_EXPIRED);
	bst_jwks_free(hk);
}

TEST(alg_none)
{
	bst_jwt_cfg c = cfg();
	const char *algs[] = { "none", "None", "NONE", "nOnE" };
	char h[64], p[128], t[512];
	for (size_t i = 0; i < 4; i++) {
		char hdr[64];
		snprintf(hdr, sizeof hdr, "{\"alg\":\"%s\"}", algs[i]);
		b64u(hdr, strlen(hdr), h, sizeof h);
		b64u(PAY, strlen(PAY), p, sizeof p);
		snprintf(t, sizeof t, "%s.%s.", h, p);
		ASSERT(verify(t, &c, NOW) != BST_JWT_OK);
		snprintf(t, sizeof t, "%s.%s.AAAA", h, p);
		ASSERT_EQ(verify(t, &c, NOW), BST_JWT_ALG);
	}
}

TEST(alg_confusion)
{
	bst_jwt_cfg c = cfg();
	c.algs |= BST_JWT_HS256; /* even if HS256 were allowed, an RSA key never verifies it */
	char t[4096];
	sign(t, sizeof t, "{\"alg\":\"HS256\",\"kid\":\"rsa1\"}", PAY, NULL, "HS256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_KEY);
}

TEST(alg_not_allowed)
{
	bst_jwt_cfg c = cfg();
	c.algs = BST_JWT_ES256;
	char t[4096];
	sign(t, sizeof t, "{\"alg\":\"RS256\",\"kid\":\"rsa1\"}", PAY, rsa_key, "RS256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_ALG);
	/* ES256 key presented as RS256 */
	sign(t, sizeof t, "{\"alg\":\"RS256\",\"kid\":\"ec1\"}", PAY, rsa_key, "RS256");
	c.algs = BST_JWT_RS256;
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_KEY);
}

TEST(kid_lookup)
{
	bst_jwt_cfg c = cfg();
	char t[4096];
	sign(t, sizeof t, "{\"alg\":\"ES256\",\"kid\":\"nope\"}", PAY, ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_KEY);
	sign(t, sizeof t, "{\"alg\":\"ES256\"}", PAY, ec_key, "ES256"); /* one ES256 key: picked */
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_OK);
	sign(t, sizeof t, "{\"alg\":\"ES256\",\"kid\":\"ec1\"}", PAY, ed_key, "EdDSA");
	ASSERT(verify(t, &c, NOW) != BST_JWT_OK); /* wrong key's signature */
}

TEST(exp_nbf_iat)
{
	bst_jwt_cfg c = cfg();
	char t[4096];
	sign(t, sizeof t, "{\"alg\":\"ES256\"}", "{\"exp\":1000,\"nbf\":900,\"iat\":900}", ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, 999), BST_JWT_OK);
	ASSERT_EQ(verify(t, &c, 1000), BST_JWT_EXPIRED); /* exp is exclusive */
	ASSERT_EQ(verify(t, &c, 899), BST_JWT_NOT_YET);
	c.leeway_s = 10;
	ASSERT_EQ(verify(t, &c, 1009), BST_JWT_OK);
	ASSERT_EQ(verify(t, &c, 1010), BST_JWT_EXPIRED);
	ASSERT_EQ(verify(t, &c, 890), BST_JWT_OK);
	ASSERT_EQ(verify(t, &c, 889), BST_JWT_NOT_YET);
	sign(t, sizeof t, "{\"alg\":\"ES256\"}", "{\"exp\":\"1000\"}", ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, 1), BST_JWT_MALFORMED);
}

TEST(iss_aud)
{
	bst_jwt_cfg c = cfg();
	const char *aud[] = { "api", "web" };
	c.iss = "https://idp";
	c.aud = aud;
	c.naud = 2;
	char t[4096];
	sign(t, sizeof t, "{\"alg\":\"ES256\"}", "{\"iss\":\"https://idp\",\"aud\":\"web\"}", ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_OK);
	sign(t, sizeof t, "{\"alg\":\"ES256\"}", "{\"iss\":\"https://idp\",\"aud\":[\"x\",\"api\"]}", ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_OK);
	sign(t, sizeof t, "{\"alg\":\"ES256\"}", "{\"iss\":\"https://idp\",\"aud\":[\"x\"]}", ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_AUD);
	sign(t, sizeof t, "{\"alg\":\"ES256\"}", "{\"iss\":\"https://evil\",\"aud\":\"api\"}", ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_ISS);
	sign(t, sizeof t, "{\"alg\":\"ES256\"}", "{\"iss\":\"https://idp\"}", ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_AUD);
}

TEST(duplicate_claims)
{
	bst_jwt_cfg c = cfg();
	char t[4096];
	sign(t, sizeof t, "{\"alg\":\"ES256\"}", "{\"sub\":\"a\",\"sub\":\"admin\"}", ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_MALFORMED);
	sign(t, sizeof t, "{\"alg\":\"ES256\",\"alg\":\"ES256\"}", PAY, ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_MALFORMED);
}

TEST(malformed)
{
	bst_jwt_cfg c = cfg();
	char t[4096];
	sign(t, sizeof t, "{\"alg\":\"ES256\"}", PAY, ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_OK);
	char u[4200];
	snprintf(u, sizeof u, "%s.x", t);
	ASSERT_EQ(verify(u, &c, NOW), BST_JWT_MALFORMED); /* four segments */
	ASSERT_EQ(verify("a.b", &c, NOW), BST_JWT_MALFORMED);
	ASSERT_EQ(verify("", &c, NOW), BST_JWT_MALFORMED);
	snprintf(u, sizeof u, "%s=", t);
	ASSERT_EQ(verify(u, &c, NOW), BST_JWT_MALFORMED); /* padding */
	strcpy(u, t);
	u[3] = '*';
	ASSERT_EQ(verify(u, &c, NOW), BST_JWT_MALFORMED); /* bad base64url */
	static char big[1 << 20];
	memset(big, 'A', sizeof big - 1);
	big[100] = big[200] = '.';
	ASSERT_EQ(verify(big, &c, NOW), BST_JWT_MALFORMED); /* 1 MiB: refused before work */
}

TEST(crit_header)
{
	bst_jwt_cfg c = cfg();
	char t[4096];
	sign(t, sizeof t, "{\"alg\":\"ES256\",\"crit\":[\"exp\"],\"exp\":1}", PAY, ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_CRIT);
}

TEST(required_claim)
{
	bst_jwt_cfg c = cfg();
	const char *req[] = { "email" };
	c.required = req;
	c.nrequired = 1;
	char t[4096];
	sign(t, sizeof t, "{\"alg\":\"ES256\"}", PAY, ec_key, "ES256");
	ASSERT_EQ(verify(t, &c, NOW), BST_JWT_CLAIM);
	bst_jwks_free(keys);
	EVP_PKEY_free(ec_key);
	EVP_PKEY_free(rsa_key);
	EVP_PKEY_free(ed_key);
}

TAP_MAIN()

/* The cryptography and the small parsers of the ACME job (ops/acme.h): JWS, JWK thumbprints,
 * external account binding, keys, CSRs, self-signed certificates, backoff and time formats. */
#include "ops/acme.h"

#include "core/b64.h"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

char *bst_acme_b64url(const void *p, size_t n)
{
	size_t cap = (n + 2) / 3 * 4 + 1;
	char *out = malloc(cap);
	if (out == NULL)
		return NULL;
	if (n == 0) {
		out[0] = '\0';
		return out;
	}
	if (bst_b64_encode(p, n, out, cap, BST_B64_URL, false) == 0) {
		free(out);
		return NULL;
	}
	return out;
}

static char *dupf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static char *dupf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char *s = NULL;
	if (vasprintf(&s, fmt, ap) < 0)
		s = NULL;
	va_end(ap);
	return s;
}

static bool ec_xy(EVP_PKEY *k, unsigned char x[32], unsigned char y[32])
{
	BIGNUM *bx = NULL, *by = NULL;
	bool ok = EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_PUB_X, &bx) == 1 &&
		  EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_EC_PUB_Y, &by) == 1 &&
		  BN_bn2binpad(bx, x, 32) == 32 && BN_bn2binpad(by, y, 32) == 32;
	BN_free(bx);
	BN_free(by);
	return ok;
}

char *bst_acme_jwk(void *pkey)
{
	unsigned char x[32], y[32];
	if (!ec_xy(pkey, x, y))
		return NULL;
	char *bx = bst_acme_b64url(x, 32), *by = bst_acme_b64url(y, 32);
	char *out = NULL;
	if (bx != NULL && by != NULL) /* members in lexicographic order, no spaces: RFC 7638 */
		out = dupf("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", bx, by);
	free(bx);
	free(by);
	return out;
}

char *bst_acme_thumbprint(void *pkey)
{
	char *jwk = bst_acme_jwk(pkey);
	if (jwk == NULL)
		return NULL;
	unsigned char d[32];
	unsigned int dl = 0;
	bool ok = EVP_Digest(jwk, strlen(jwk), d, &dl, EVP_sha256(), NULL) == 1;
	free(jwk);
	return ok ? bst_acme_b64url(d, dl) : NULL;
}

/* ES256: the DER signature as the raw r || s of RFC 7518 section 3.4. */
static char *es256(EVP_PKEY *k, const char *data, size_t len)
{
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	unsigned char der[128];
	size_t dl = sizeof der;
	char *out = NULL;
	if (md == NULL || EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, k) != 1 ||
	    EVP_DigestSign(md, der, &dl, (const unsigned char *)data, len) != 1)
		goto out;
	const unsigned char *p = der;
	ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)dl);
	if (sig == NULL)
		goto out;
	unsigned char raw[64];
	if (BN_bn2binpad(ECDSA_SIG_get0_r(sig), raw, 32) == 32 &&
	    BN_bn2binpad(ECDSA_SIG_get0_s(sig), raw + 32, 32) == 32)
		out = bst_acme_b64url(raw, 64);
	ECDSA_SIG_free(sig);
out:
	EVP_MD_CTX_free(md);
	ERR_clear_error();
	return out;
}

static char *flatten(const char *prot_json, const char *payload, char *(*sign)(const void *, const char *, size_t),
		     const void *key)
{
	char *p64 = bst_acme_b64url(prot_json, strlen(prot_json));
	char *b64 = payload != NULL ? bst_acme_b64url(payload, strlen(payload)) : strdup("");
	char *signing = NULL, *sig = NULL, *out = NULL;
	if (p64 == NULL || b64 == NULL)
		goto out;
	signing = dupf("%s.%s", p64, b64);
	if (signing == NULL)
		goto out;
	sig = sign(key, signing, strlen(signing));
	if (sig != NULL)
		out = dupf("{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}", p64, b64, sig);
out:
	free(p64);
	free(b64);
	free(signing);
	free(sig);
	return out;
}

static char *sign_es256(const void *key, const char *data, size_t len)
{
	return es256((EVP_PKEY *)(uintptr_t)key, data, len);
}

/* JSON string contents: the values here are URLs, nonces and key ids from the CA or the config;
 * anything that would need escaping is refused rather than escaped. */
static bool plain(const char *s)
{
	for (; *s; s++)
		if ((unsigned char)*s < 0x20 || *s == '"' || *s == '\\' || (unsigned char)*s >= 0x7f)
			return false;
	return true;
}

char *bst_acme_jws(void *pkey, const char *kid, const char *nonce, const char *url, const char *payload)
{
	if (!plain(nonce) || !plain(url) || (kid != NULL && !plain(kid)))
		return NULL;
	char *prot;
	if (kid != NULL) {
		prot = dupf("{\"alg\":\"ES256\",\"kid\":\"%s\",\"nonce\":\"%s\",\"url\":\"%s\"}", kid, nonce, url);
	} else {
		char *jwk = bst_acme_jwk(pkey);
		if (jwk == NULL)
			return NULL;
		prot = dupf("{\"alg\":\"ES256\",\"jwk\":%s,\"nonce\":\"%s\",\"url\":\"%s\"}", jwk, nonce, url);
		free(jwk);
	}
	if (prot == NULL)
		return NULL;
	char *out = flatten(prot, payload, sign_es256, pkey);
	free(prot);
	return out;
}

typedef struct hkey {
	unsigned char k[256];
	long n;
} hkey;

static char *sign_hs256(const void *key, const char *data, size_t len)
{
	const hkey *h = key;
	unsigned char mac[32];
	unsigned int ml = 0;
	if (HMAC(EVP_sha256(), h->k, (int)h->n, (const unsigned char *)data, len, mac, &ml) == NULL)
		return NULL;
	return bst_acme_b64url(mac, ml);
}

char *bst_acme_eab(void *pkey, const char *kid, const char *hmac_b64url, const char *url)
{
	hkey h;
	h.n = bst_b64_decode(hmac_b64url, strlen(hmac_b64url), h.k, sizeof h.k,
			     BST_B64_URL | BST_B64_PAD_OPTIONAL);
	if (h.n <= 0 || !plain(kid) || !plain(url))
		return NULL;
	char *jwk = bst_acme_jwk(pkey);
	if (jwk == NULL)
		return NULL;
	char *prot = dupf("{\"alg\":\"HS256\",\"kid\":\"%s\",\"url\":\"%s\"}", kid, url);
	char *out = prot != NULL ? flatten(prot, jwk, sign_hs256, &h) : NULL;
	OPENSSL_cleanse(&h, sizeof h);
	free(prot);
	free(jwk);
	return out;
}

void *bst_acme_keygen(bst_acme_key_type t)
{
	EVP_PKEY *k = t == BST_ACME_KEY_RSA2048 ? EVP_RSA_gen(2048) : EVP_EC_gen("P-256");
	ERR_clear_error();
	return k;
}

char *bst_acme_key_pem(void *pkey, size_t *len)
{
	BIO *b = BIO_new(BIO_s_mem());
	char *out = NULL;
	if (b != NULL && PEM_write_bio_PrivateKey(b, pkey, NULL, NULL, 0, NULL, NULL) == 1) {
		char *p;
		long n = BIO_get_mem_data(b, &p);
		out = malloc((size_t)n + 1);
		if (out != NULL) {
			memcpy(out, p, (size_t)n);
			out[n] = '\0';
			*len = (size_t)n;
		}
	}
	BIO_free(b); /* a memory BIO: OpenSSL clears its buffer only when told; the key is ours */
	ERR_clear_error();
	return out;
}

void *bst_acme_key_from_pem(const char *pem, size_t len)
{
	BIO *b = BIO_new_mem_buf(pem, (int)len);
	EVP_PKEY *k = b != NULL ? PEM_read_bio_PrivateKey(b, NULL, NULL, NULL) : NULL;
	BIO_free(b);
	ERR_clear_error();
	return k;
}

void bst_acme_key_free(void *pkey)
{
	EVP_PKEY_free(pkey);
}

static GENERAL_NAMES *sans(const char *const *names, size_t n)
{
	GENERAL_NAMES *g = GENERAL_NAMES_new();
	for (size_t i = 0; g != NULL && i < n; i++) {
		GENERAL_NAME *one = GENERAL_NAME_new();
		ASN1_IA5STRING *s = ASN1_IA5STRING_new();
		if (one == NULL || s == NULL || ASN1_STRING_set(s, names[i], (int)strlen(names[i])) != 1) {
			GENERAL_NAME_free(one);
			ASN1_IA5STRING_free(s);
			GENERAL_NAMES_free(g);
			return NULL;
		}
		GENERAL_NAME_set0_value(one, GEN_DNS, s);
		if (sk_GENERAL_NAME_push(g, one) == 0) {
			GENERAL_NAME_free(one);
			GENERAL_NAMES_free(g);
			return NULL;
		}
	}
	return g;
}

static bool set_cn(X509_NAME *nm, const char *cn)
{
	size_t l = strlen(cn);
	return X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_UTF8, (const unsigned char *)cn,
					  l > 64 ? 64 : (int)l, -1, 0) == 1;
}

char *bst_acme_csr(void *pkey, const char *const *names, size_t n)
{
	X509_REQ *r = X509_REQ_new();
	STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
	GENERAL_NAMES *g = sans(names, n);
	unsigned char *der = NULL;
	char *out = NULL;
	if (r == NULL || exts == NULL || g == NULL || n == 0)
		goto out;
	X509_EXTENSION *ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, g);
	if (ext == NULL || sk_X509_EXTENSION_push(exts, ext) == 0) {
		X509_EXTENSION_free(ext);
		goto out;
	}
	if (X509_REQ_set_version(r, X509_REQ_VERSION_1) != 1 || !set_cn(X509_REQ_get_subject_name(r), names[0]) ||
	    X509_REQ_set_pubkey(r, pkey) != 1 || X509_REQ_add_extensions(r, exts) != 1 ||
	    X509_REQ_sign(r, pkey, EVP_sha256()) <= 0)
		goto out;
	int dl = i2d_X509_REQ(r, &der);
	if (dl > 0)
		out = bst_acme_b64url(der, (size_t)dl);
out:
	OPENSSL_free(der);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	GENERAL_NAMES_free(g);
	X509_REQ_free(r);
	ERR_clear_error();
	return out;
}

char *bst_acme_selfsigned(void *pkey, const char *const *names, size_t n, int days, size_t *len)
{
	X509 *x = X509_new();
	GENERAL_NAMES *g = sans(names, n);
	BIO *b = NULL;
	char *out = NULL;
	unsigned char serial[16];
	if (x == NULL || g == NULL || n == 0 || RAND_bytes(serial, sizeof serial) != 1)
		goto out;
	serial[0] &= 0x7f;
	BIGNUM *bn = BN_bin2bn(serial, sizeof serial, NULL);
	ASN1_INTEGER *ai = bn != NULL ? BN_to_ASN1_INTEGER(bn, NULL) : NULL;
	BN_free(bn);
	if (ai == NULL)
		goto out;
	int ok = X509_set_serialNumber(x, ai);
	ASN1_INTEGER_free(ai);
	if (ok != 1 || X509_set_version(x, X509_VERSION_3) != 1 ||
	    X509_gmtime_adj(X509_getm_notBefore(x), -3600) == NULL ||
	    X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 86400) == NULL ||
	    !set_cn(X509_get_subject_name(x), names[0]) ||
	    X509_set_issuer_name(x, X509_get_subject_name(x)) != 1 || X509_set_pubkey(x, pkey) != 1 ||
	    X509_add1_ext_i2d(x, NID_subject_alt_name, g, 0, X509V3_ADD_DEFAULT) != 1 ||
	    X509_sign(x, pkey, EVP_sha256()) <= 0)
		goto out;
	b = BIO_new(BIO_s_mem());
	if (b == NULL || PEM_write_bio_X509(b, x) != 1)
		goto out;
	char *p;
	long bl = BIO_get_mem_data(b, &p);
	out = malloc((size_t)bl + 1);
	if (out != NULL) {
		memcpy(out, p, (size_t)bl);
		out[bl] = '\0';
		*len = (size_t)bl;
	}
out:
	BIO_free(b);
	GENERAL_NAMES_free(g);
	X509_free(x);
	ERR_clear_error();
	return out;
}

uint64_t bst_acme_backoff_s(unsigned fails, uint64_t retry_after_s, uint64_t base_s)
{
	const uint64_t cap = 86400;
	uint64_t d = base_s == 0 ? 1 : base_s;
	for (unsigned i = 1; i < fails && d < cap; i++)
		d *= 2;
	if (d > cap)
		d = cap;
	return retry_after_s > d ? retry_after_s : d;
}

bool bst_acme_retry_after(const char *v, int64_t now, uint64_t *out_s)
{
	size_t n = strlen(v);
	if (n == 0)
		return false;
	bool digits = true;
	for (size_t i = 0; i < n; i++)
		digits &= v[i] >= '0' && v[i] <= '9';
	if (digits) {
		if (n > 9)
			return false;
		*out_s = strtoull(v, NULL, 10);
		return true;
	}
	struct tm tm;
	memset(&tm, 0, sizeof tm);
	const char *end = strptime(v, "%a, %d %b %Y %H:%M:%S GMT", &tm);
	if (end == NULL || *end != '\0')
		return false;
	int64_t t = (int64_t)timegm(&tm);
	*out_s = t > now ? (uint64_t)(t - now) : 0;
	return true;
}

static bool num(const char *s, size_t n, int *out)
{
	int v = 0;
	for (size_t i = 0; i < n; i++) {
		if (s[i] < '0' || s[i] > '9')
			return false;
		v = v * 10 + (s[i] - '0');
	}
	*out = v;
	return true;
}

bool bst_acme_rfc3339(const char *s, size_t len, int64_t *out)
{
	/* YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM) */
	if (len < 20 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != 't') || s[13] != ':' ||
	    s[16] != ':')
		return false;
	struct tm tm;
	memset(&tm, 0, sizeof tm);
	int y, mo, d, h, mi, se;
	if (!num(s, 4, &y) || !num(s + 5, 2, &mo) || !num(s + 8, 2, &d) || !num(s + 11, 2, &h) ||
	    !num(s + 14, 2, &mi) || !num(s + 17, 2, &se) || mo < 1 || mo > 12 || d < 1 || d > 31 ||
	    h > 23 || mi > 59 || se > 60)
		return false;
	size_t i = 19;
	if (i < len && s[i] == '.') {
		i++;
		size_t f = i;
		while (i < len && s[i] >= '0' && s[i] <= '9')
			i++;
		if (i == f)
			return false;
	}
	int64_t off = 0;
	if (i < len && (s[i] == 'Z' || s[i] == 'z')) {
		i++;
	} else if (i + 6 == len && (s[i] == '+' || s[i] == '-') && s[i + 3] == ':') {
		int oh, om;
		if (!num(s + i + 1, 2, &oh) || !num(s + i + 4, 2, &om) || oh > 23 || om > 59)
			return false;
		off = (int64_t)(oh * 3600 + om * 60) * (s[i] == '+' ? 1 : -1);
		i += 6;
	} else {
		return false;
	}
	if (i != len)
		return false;
	tm.tm_year = y - 1900;
	tm.tm_mon = mo - 1;
	tm.tm_mday = d;
	tm.tm_hour = h;
	tm.tm_min = mi;
	tm.tm_sec = se;
	*out = (int64_t)timegm(&tm) - off;
	return true;
}

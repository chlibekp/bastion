/* The ACME job's protocol pieces (src/ops/acme_crypto.c, acme_http01.c, http_client.c): JWS and
 * thumbprints checked with OpenSSL, the challenge table, backoff and Retry-After, RFC 3339 times,
 * and the response parser's limits. The protocol end to end runs against Pebble in
 * tests/integration/test_acme.py. */
#include "core/b64.h"
#include "ops/acme.h"
#include "ops/acme_priv.h"
#include "ops/http_client.h"
#include "tap.h"

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static size_t unb64(const char *s, size_t n, unsigned char *out, size_t cap)
{
	long r = bst_b64_decode(s, n, out, cap, BST_B64_URL | BST_B64_PAD_FORBIDDEN);
	return r < 0 ? (size_t)-1 : (size_t)r;
}

/* The JSON string value of "key" in a flat object (test inputs only). */
static char *field(const char *json, const char *key)
{
	char pat[64];
	snprintf(pat, sizeof pat, "\"%s\":\"", key);
	const char *p = strstr(json, pat);
	if (p == NULL)
		return NULL;
	p += strlen(pat);
	return strndup(p, (size_t)(strchr(p, '"') - p));
}

TEST(jws_es256_verifies)
{
	EVP_PKEY *k = bst_acme_keygen(BST_ACME_KEY_P256);
	ASSERT(k != NULL);
	char *jws = bst_acme_jws(k, "https://ca/acct/1", "nonce-1", "https://ca/order", "{\"a\":1}");
	ASSERT(jws != NULL);
	char *prot = field(jws, "protected"), *pay = field(jws, "payload"), *sig = field(jws, "signature");
	ASSERT(prot && pay && sig);
	unsigned char hdr[512], raw[64];
	size_t hl = unb64(prot, strlen(prot), hdr, sizeof hdr - 1);
	ASSERT(hl != (size_t)-1);
	hdr[hl] = 0;
	ASSERT_STR((char *)hdr, "{\"alg\":\"ES256\",\"kid\":\"https://ca/acct/1\",\"nonce\":\"nonce-1\","
				"\"url\":\"https://ca/order\"}");
	ASSERT_EQ(unb64(sig, strlen(sig), raw, sizeof raw), 64);
	/* raw r || s back to DER, verified over "protected.payload" */
	ECDSA_SIG *es = ECDSA_SIG_new();
	ECDSA_SIG_set0(es, BN_bin2bn(raw, 32, NULL), BN_bin2bn(raw + 32, 32, NULL));
	unsigned char *der = NULL;
	int dl = i2d_ECDSA_SIG(es, &der);
	char signing[1024];
	snprintf(signing, sizeof signing, "%s.%s", prot, pay);
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	ASSERT_EQ(EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, k), 1);
	ASSERT_EQ(EVP_DigestVerify(md, der, (size_t)dl, (unsigned char *)signing, strlen(signing)), 1);
	signing[0] ^= 1; /* any other input fails */
	ASSERT(EVP_DigestVerify(md, der, (size_t)dl, (unsigned char *)signing, strlen(signing)) != 1);
	EVP_MD_CTX_free(md);
	OPENSSL_free(der);
	ECDSA_SIG_free(es);
	free(prot), free(pay), free(sig), free(jws);
	/* POST-as-GET: empty payload; no kid: the JWK in the header */
	jws = bst_acme_jws(k, NULL, "n", "https://ca/x", NULL);
	pay = field(jws, "payload");
	ASSERT_STR(pay, "");
	prot = field(jws, "protected");
	hl = unb64(prot, strlen(prot), hdr, sizeof hdr - 1);
	hdr[hl] = 0;
	ASSERT(strstr((char *)hdr, "\"jwk\":{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"") != NULL);
	free(pay), free(prot), free(jws);
	/* a nonce or URL that would need escaping is refused, not escaped */
	ASSERT(bst_acme_jws(k, NULL, "a\"b", "https://ca/x", NULL) == NULL);
	ASSERT(bst_acme_jws(k, NULL, "n", "https://ca/x\n", NULL) == NULL);
	bst_acme_key_free(k);
}

TEST(thumbprint_is_sha256_of_canonical_jwk)
{
	EVP_PKEY *k = bst_acme_keygen(BST_ACME_KEY_P256);
	char *jwk = bst_acme_jwk(k), *tp = bst_acme_thumbprint(k);
	ASSERT(jwk && tp);
	unsigned char d[32];
	unsigned int dl = 0;
	EVP_Digest(jwk, strlen(jwk), d, &dl, EVP_sha256(), NULL);
	char *want = bst_acme_b64url(d, dl);
	ASSERT_STR(tp, want);
	ASSERT_EQ(strlen(tp), 43);
	free(jwk), free(tp), free(want);
	/* an RSA key has no P-256 JWK */
	EVP_PKEY *r = bst_acme_keygen(BST_ACME_KEY_RSA2048);
	ASSERT(r != NULL);
	ASSERT(bst_acme_thumbprint(r) == NULL);
	bst_acme_key_free(r);
	bst_acme_key_free(k);
}

TEST(eab_needs_base64url_key)
{
	EVP_PKEY *k = bst_acme_keygen(BST_ACME_KEY_P256);
	char *e = bst_acme_eab(k, "kid-1", "c2VjcmV0LWtleS0xMjM0NTY3ODkw", "https://ca/new-acct");
	ASSERT(e != NULL);
	ASSERT(strstr(e, "\"signature\":\"") != NULL);
	ASSERT(bst_acme_eab(k, "kid-1", "not base64!", "https://ca/new-acct") == NULL);
	free(e);
	bst_acme_key_free(k);
}

TEST(csr_and_selfsigned)
{
	EVP_PKEY *k = bst_acme_keygen(BST_ACME_KEY_P256);
	const char *names[] = { "a.example.test", "b.example.test" };
	char *csr = bst_acme_csr(k, names, 2);
	ASSERT(csr != NULL && strlen(csr) > 100);
	ASSERT(strchr(csr, '=') == NULL && strchr(csr, '+') == NULL); /* base64url, unpadded */
	size_t n = 0;
	char *pem = bst_acme_selfsigned(k, names, 2, 90, &n);
	ASSERT(pem != NULL && n > 0 && strncmp(pem, "-----BEGIN CERTIFICATE-----", 27) == 0);
	ASSERT(bst_acme_csr(k, names, 0) == NULL);
	free(csr), free(pem);
	bst_acme_key_free(k);
}

TEST(backoff_doubles_caps_and_honours_retry_after)
{
	ASSERT_EQ(bst_acme_backoff_s(1, 0, 60), 60);
	ASSERT_EQ(bst_acme_backoff_s(2, 0, 60), 120);
	ASSERT_EQ(bst_acme_backoff_s(5, 0, 60), 960);
	ASSERT_EQ(bst_acme_backoff_s(40, 0, 60), 86400);  /* a day at most */
	ASSERT_EQ(bst_acme_backoff_s(1, 3600, 60), 3600); /* never below the CA's Retry-After */
	ASSERT_EQ(bst_acme_backoff_s(3, 10, 60), 240);
	uint64_t s = 0;
	ASSERT(bst_acme_retry_after("120", 0, &s) && s == 120);
	ASSERT(bst_acme_retry_after("Thu, 01 Jan 1970 00:10:00 GMT", 60, &s) && s == 540);
	ASSERT(bst_acme_retry_after("Thu, 01 Jan 1970 00:00:10 GMT", 60, &s) && s == 0); /* past */
	ASSERT(!bst_acme_retry_after("", 0, &s));
	ASSERT(!bst_acme_retry_after("-5", 0, &s));
	ASSERT(!bst_acme_retry_after("12345678901", 0, &s));
}

TEST(rfc3339)
{
	int64_t t = 0;
	ASSERT(bst_acme_rfc3339("1970-01-02T00:00:00Z", 20, &t) && t == 86400);
	ASSERT(bst_acme_rfc3339("1970-01-02T00:00:00.123456Z", 27, &t) && t == 86400);
	ASSERT(bst_acme_rfc3339("1970-01-02T02:00:00+02:00", 25, &t) && t == 86400);
	ASSERT(!bst_acme_rfc3339("1970-01-02 00:00:00Z", 20, &t));
	ASSERT(!bst_acme_rfc3339("1970-13-02T00:00:00Z", 20, &t));
	ASSERT(!bst_acme_rfc3339("1970-01-02T00:00:00", 19, &t));
}

TEST(http01_table_serves_known_tokens_only)
{
	static bst_acme_region region;
	bst_acme_region_ = &region;
	char out[BST_ACME_KEYAUTH_MAX];
	ASSERT_EQ(bst_acme_http01_put(BST_S("tok_1-A"), BST_S("tok_1-A.thumb")), 0);
	ASSERT_EQ(bst_acme_http01_get(BST_S("tok_1-A"), out, sizeof out), 13);
	ASSERT(memcmp(out, "tok_1-A.thumb", 13) == 0);
	ASSERT_EQ(bst_acme_http01_get(BST_S("tok_1-B"), out, sizeof out), -1);
	ASSERT_EQ(bst_acme_http01_get(BST_S("tok_1"), out, sizeof out), -1); /* no prefix match */
	/* never a path: dots, slashes, percent signs are not base64url */
	ASSERT(!bst_acme_token_valid(BST_S("../x")));
	ASSERT(!bst_acme_token_valid(BST_S("a%2Fb")));
	ASSERT(!bst_acme_token_valid(BST_S("a.b")));
	ASSERT(!bst_acme_token_valid(BST_S("")));
	ASSERT_EQ(bst_acme_http01_put(BST_S("../etc"), BST_S("x")), -1);
	bst_acme_http01_remove(BST_S("tok_1-A"));
	ASSERT_EQ(bst_acme_http01_get(BST_S("tok_1-A"), out, sizeof out), -1);
	/* full table */
	char tok[16];
	for (int i = 0; i < BST_ACME_TOKENS; i++) {
		snprintf(tok, sizeof tok, "t%d", i);
		ASSERT_EQ(bst_acme_http01_put((bst_str){ tok, (uint32_t)strlen(tok) }, BST_S("v")), 0);
	}
	ASSERT_EQ(bst_acme_http01_put(BST_S("one-more"), BST_S("v")), -1);
	bst_acme_region_ = NULL;
	ASSERT_EQ(bst_acme_http01_get(BST_S("t1"), out, sizeof out), -1); /* no region: nothing */
}

TEST(response_parser)
{
	bst_hc_resp r;
	char err[128];
	memset(&r, 0, sizeof r);
	const char ok[] = "HTTP/1.1 201 Created\r\nLocation: https://ca/o/1\r\nReplay-Nonce: abc\r\n"
			  "Link: <https://ca/issuer>;rel=\"up\"\r\nContent-Length: 2\r\n\r\n{}";
	ASSERT_EQ(bst_hc_parse_response(ok, sizeof ok - 1, false, &r, err, sizeof err), 0);
	ASSERT_EQ(r.status, 201);
	ASSERT_STR(r.location, "https://ca/o/1");
	ASSERT_STR(r.nonce, "abc");
	ASSERT_STR(r.link_up, "https://ca/issuer");
	ASSERT_STR(r.body, "{}");
	bst_hc_resp_free(&r);
	const char ch[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n";
	ASSERT_EQ(bst_hc_parse_response(ch, sizeof ch - 1, false, &r, err, sizeof err), 0);
	ASSERT_STR(r.body, "abcde");
	bst_hc_resp_free(&r);
	const char trunc[] = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
	ASSERT_EQ(bst_hc_parse_response(trunc, sizeof trunc - 1, false, &r, err, sizeof err), -1);
	const char big[] = "HTTP/1.1 200 OK\r\nContent-Length: 9999999\r\n\r\n";
	ASSERT_EQ(bst_hc_parse_response(big, sizeof big - 1, false, &r, err, sizeof err), -1);
	ASSERT(strstr(err, "larger than") != NULL);
	const char two[] = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab";
	ASSERT_EQ(bst_hc_parse_response(two, sizeof two - 1, false, &r, err, sizeof err), -1);
	const char junk[] = "SSH-2.0-OpenSSH\r\n\r\n";
	ASSERT_EQ(bst_hc_parse_response(junk, sizeof junk - 1, false, &r, err, sizeof err), -1);
	const char head[] = "HTTP/1.1 200 OK\r\nReplay-Nonce: n2\r\nContent-Length: 50\r\n\r\n";
	ASSERT_EQ(bst_hc_parse_response(head, sizeof head - 1, true, &r, err, sizeof err), 0);
	ASSERT_STR(r.nonce, "n2");
	bst_hc_resp_free(&r);
}

/* ---- an install a crash interrupted (bst_acme_recover_pair) ---- */

static void put(const char *root, const char *leaf, const char *text)
{
	char p[512];
	snprintf(p, sizeof p, "%s/certs/a/%s", root, leaf);
	FILE *f = fopen(p, "w");
	if (f != NULL) {
		fputs(text, f);
		fclose(f);
	}
}

/* The file's first line, or "" when it does not exist. */
static const char *got(const char *root, const char *leaf)
{
	static char buf[64];
	char p[512];
	snprintf(p, sizeof p, "%s/certs/a/%s", root, leaf);
	buf[0] = '\0';
	FILE *f = fopen(p, "r");
	if (f != NULL) {
		if (fgets(buf, sizeof buf, f) == NULL)
			buf[0] = '\0';
		fclose(f);
	}
	return buf;
}

static int storage(char *root, size_t cap)
{
	snprintf(root, cap, "%s", "/tmp/bst-acme-pair-XXXXXX");
	if (mkdtemp(root) == NULL)
		return -1;
	char p[512];
	snprintf(p, sizeof p, "%s/certs", root);
	mkdir(p, 0700);
	snprintf(p, sizeof p, "%s/certs/a", root);
	mkdir(p, 0700);
	put(root, "cert.pem", "old");
	put(root, "key.pem", "old");
	return open(root, O_RDONLY | O_DIRECTORY);
}

static void wipe(const char *root)
{
	const char *leaves[] = { "cert.pem", "key.pem", "cert.pem.next", "key.pem.next", "commit" };
	char p[512];
	for (size_t i = 0; i < sizeof leaves / sizeof leaves[0]; i++) {
		snprintf(p, sizeof p, "%s/certs/a/%s", root, leaves[i]);
		unlink(p);
	}
	snprintf(p, sizeof p, "%s/certs/a", root);
	rmdir(p);
	snprintf(p, sizeof p, "%s/certs", root);
	rmdir(p);
	rmdir(root);
}

TEST(acme_pair_untouched_without_an_install)
{
	char root[64];
	int d = storage(root, sizeof root);
	ASSERT(d >= 0);
	ASSERT_EQ(bst_acme_recover_pair(d, "certs/a"), 0);
	ASSERT_STR(got(root, "cert.pem"), "old");
	ASSERT_STR(got(root, "key.pem"), "old");
	close(d);
	wipe(root);
}

TEST(acme_pair_uncommitted_install_is_discarded)
{
	char root[64];
	int d = storage(root, sizeof root);
	ASSERT(d >= 0);
	put(root, "key.pem.next", "new"); /* crashed before the cert and the marker */
	ASSERT_EQ(bst_acme_recover_pair(d, "certs/a"), 2);
	ASSERT_STR(got(root, "cert.pem"), "old");
	ASSERT_STR(got(root, "key.pem"), "old");
	ASSERT_STR(got(root, "key.pem.next"), "");
	close(d);
	wipe(root);
}

TEST(acme_pair_committed_install_is_finished_after_a_crash_between_renames)
{
	char root[64];
	int d = storage(root, sizeof root);
	ASSERT(d >= 0);
	/* the key was renamed in, then the crash: the stored pair disagrees until recovery */
	put(root, "key.pem", "new");
	put(root, "cert.pem.next", "new");
	put(root, "commit", "");
	ASSERT_EQ(bst_acme_recover_pair(d, "certs/a"), 1);
	ASSERT_STR(got(root, "cert.pem"), "new");
	ASSERT_STR(got(root, "key.pem"), "new");
	ASSERT_STR(got(root, "cert.pem.next"), "");
	ASSERT_EQ(faccessat(d, "certs/a/commit", F_OK, 0), -1);
	/* both halves pending */
	put(root, "key.pem.next", "newer");
	put(root, "cert.pem.next", "newer");
	put(root, "commit", "");
	ASSERT_EQ(bst_acme_recover_pair(d, "certs/a"), 1);
	ASSERT_STR(got(root, "cert.pem"), "newer");
	ASSERT_STR(got(root, "key.pem"), "newer");
	ASSERT_EQ(bst_acme_recover_pair(d, "certs/a"), 0);
	close(d);
	wipe(root);
}

TEST(acme_pair_recovery_stays_beneath_the_storage_directory)
{
	char root[64];
	int d = storage(root, sizeof root);
	ASSERT(d >= 0);
	ASSERT_EQ(bst_acme_recover_pair(d, "../etc"), -1);
	close(d);
	wipe(root);
}

TEST(url_parser_refuses_request_splitting)
{
	bool tls;
	char host[64], path[128];
	uint16_t port;
	ASSERT(bst_hc_parse_url("https://127.0.0.1:14000/dir", &tls, host, sizeof host, &port, path, sizeof path));
	ASSERT(tls && port == 14000);
	ASSERT_STR(host, "127.0.0.1");
	ASSERT_STR(path, "/dir");
	ASSERT(bst_hc_parse_url("http://[::1]/a?b", &tls, host, sizeof host, &port, path, sizeof path));
	ASSERT_STR(host, "::1");
	ASSERT(!tls && port == 80);
	ASSERT_STR(path, "/a?b");
	ASSERT(!bst_hc_parse_url("https://ca/a b", &tls, host, sizeof host, &port, path, sizeof path));
	ASSERT(!bst_hc_parse_url("https://ca/a\r\nX: y", &tls, host, sizeof host, &port, path, sizeof path));
	ASSERT(!bst_hc_parse_url("https://user@ca/", &tls, host, sizeof host, &port, path, sizeof path));
	ASSERT(!bst_hc_parse_url("ftp://ca/", &tls, host, sizeof host, &port, path, sizeof path));
	ASSERT(!bst_hc_parse_url("https://ca:99999/", &tls, host, sizeof host, &port, path, sizeof path));
}

TAP_MAIN()

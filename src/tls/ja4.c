#include "tls/ja4.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXT_SNI 0x0000
#define EXT_ALPN 0x0010
#define EXT_SIGALGS 0x000d
#define EXT_VERSIONS 0x002b
#define MAX_CIPHERS 8192 /* a hello is at most one record: 16 KiB */

static bool grease(uint16_t v)
{
	return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
}

static uint16_t be16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

/* ---- extension bodies ---- */

static int read_alpn(bst_client_hello *ch, const uint8_t *b, size_t n)
{
	if (n < 2 || (size_t)be16(b) != n - 2)
		return -1;
	ch->has_alpn = true;
	ch->alpn = NULL;
	ch->alpn_len = 0;
	if (n == 2)
		return 0; /* no protocol names */
	if (n < 3 || (size_t)b[2] > n - 3)
		return -1;
	ch->alpn = b + 3;
	ch->alpn_len = b[2];
	return 0;
}

static int read_sigalgs(bst_client_hello *ch, const uint8_t *b, size_t n)
{
	if (n < 2 || (size_t)be16(b) != n - 2 || (n & 1) != 0)
		return -1;
	ch->has_sigalgs = true;
	ch->sigalgs = b + 2;
	ch->sigalgs_len = n - 2;
	return 0;
}

static int read_versions(bst_client_hello *ch, const uint8_t *b, size_t n)
{
	if (n < 1 || (size_t)b[0] != n - 1 || ((n - 1) & 1) != 0)
		return -1;
	ch->has_versions = true;
	ch->versions = b + 1;
	ch->versions_len = n - 1;
	return 0;
}

static int read_ext(bst_client_hello *ch, uint16_t type, const uint8_t *b, size_t n)
{
	switch (type) {
	case EXT_SNI:
		ch->has_sni = true;
		return 0;
	case EXT_ALPN:
		return read_alpn(ch, b, n);
	case EXT_SIGALGS:
		return read_sigalgs(ch, b, n);
	case EXT_VERSIONS:
		return read_versions(ch, b, n);
	}
	return 0;
}

/* ---- the hello ---- */

int bst_client_hello_parse(const uint8_t *msg, size_t len, bst_client_hello *ch)
{
	memset(ch, 0, sizeof *ch);
	if (len < 4 || msg[0] != 1)
		return -1;
	size_t n = (size_t)msg[1] << 16 | (size_t)msg[2] << 8 | msg[3];
	if (n > len - 4)
		return -1;
	const uint8_t *p = msg + 4, *end = p + n;
	if (end - p < 2 + 32 + 1)
		return -1;
	ch->legacy_version = be16(p);
	p += 2 + 32;
	size_t sid = *p++;
	if ((size_t)(end - p) < sid + 2)
		return -1;
	p += sid;
	size_t cl = be16(p);
	p += 2;
	if ((cl & 1) != 0 || (size_t)(end - p) < cl)
		return -1;
	ch->ciphers = p;
	ch->ciphers_len = cl;
	p += cl;
	if (end - p < 1)
		return -1;
	size_t comp = *p++;
	if ((size_t)(end - p) < comp)
		return -1;
	p += comp;
	if (p == end)
		return 0; /* no extensions */
	if (end - p < 2 || (size_t)be16(p) != (size_t)(end - p) - 2)
		return -1;
	p += 2;
	while (p < end) {
		if (end - p < 4)
			return -1;
		uint16_t type = be16(p);
		size_t el = be16(p + 2);
		p += 4;
		if ((size_t)(end - p) < el || ch->next >= BST_JA4_MAX_EXT)
			return -1;
		if (read_ext(ch, type, p, el) != 0)
			return -1;
		ch->exts[ch->next++] = type;
		p += el;
	}
	return 0;
}

int bst_client_hello_from_ssl(SSL *ssl, bst_client_hello *ch)
{
	memset(ch, 0, sizeof *ch);
	ch->legacy_version = (uint16_t)SSL_client_hello_get0_legacy_version(ssl);
	ch->ciphers_len = SSL_client_hello_get0_ciphers(ssl, &ch->ciphers);
	if (ch->ciphers == NULL || (ch->ciphers_len & 1) != 0)
		return -1;
	int *types = NULL;
	size_t nt = 0;
	if (SSL_client_hello_get1_extensions_present(ssl, &types, &nt) != 1) {
		ch->ciphers = NULL;
		return -1; /* no extensions block at all is also an error here: TLS 1.3 needs one */
	}
	int rc = 0;
	if (nt > BST_JA4_MAX_EXT)
		rc = -1;
	for (size_t i = 0; rc == 0 && i < nt; i++) {
		const uint8_t *b = NULL;
		size_t n = 0;
		uint16_t t = (uint16_t)types[i];
		ch->exts[ch->next++] = t;
		if (t == EXT_SNI || t == EXT_ALPN || t == EXT_SIGALGS || t == EXT_VERSIONS) {
			if (SSL_client_hello_get0_ext(ssl, t, &b, &n) != 1)
				rc = -1;
			else
				rc = read_ext(ch, t, b, n);
		}
	}
	OPENSSL_free(types);
	return rc;
}

/* ---- the fingerprint ---- */

static int cmp16(const void *a, const void *b)
{
	uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
	return x < y ? -1 : x > y;
}

typedef struct {
	EVP_MD_CTX *c;
	bool first;
} hasher;

static void hex4(char out[5], uint16_t v)
{
	static const char d[] = "0123456789abcdef";
	out[0] = d[v >> 12];
	out[1] = d[v >> 8 & 15];
	out[2] = d[v >> 4 & 15];
	out[3] = d[v & 15];
	out[4] = '\0';
}

/* Adds ",xxxx" (no comma first) to the hash. */
static void put(hasher *h, uint16_t v)
{
	char b[5];
	if (!h->first)
		EVP_DigestUpdate(h->c, ",", 1);
	h->first = false;
	hex4(b, v);
	EVP_DigestUpdate(h->c, b, 4);
}

static int finish(hasher *h, char out[13])
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned n = 0;
	int ok = EVP_DigestFinal_ex(h->c, md, &n) == 1 && n >= 6;
	if (ok) {
		static const char d[] = "0123456789abcdef";
		for (unsigned i = 0; i < 6; i++) {
			out[2 * i] = d[md[i] >> 4];
			out[2 * i + 1] = d[md[i] & 15];
		}
		out[12] = '\0';
	}
	return ok ? 0 : -1;
}

static const char *version_name(const bst_client_hello *ch)
{
	uint16_t v = ch->legacy_version;
	if (ch->has_versions) {
		uint16_t best = 0;
		for (size_t i = 0; i < ch->versions_len; i += 2) {
			uint16_t x = be16(ch->versions + i);
			if (!grease(x) && x > best)
				best = x;
		}
		if (best != 0)
			v = best;
	}
	switch (v) {
	case 0x0304: return "13";
	case 0x0303: return "12";
	case 0x0302: return "11";
	case 0x0301: return "10";
	case 0x0300: return "s3";
	case 0x0002: return "s2";
	}
	return "00";
}

static bool alnum(uint8_t c)
{
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* First and last character of the first ALPN name; the hex of its first and last nibble when either
 * end byte is not alphanumeric ASCII (the written spec; the Python and Rust tools print "9"). */
static void alpn_chars(const bst_client_hello *ch, char out[3])
{
	out[2] = '\0';
	if (!ch->has_alpn || ch->alpn_len == 0) {
		out[0] = out[1] = '0';
		return;
	}
	uint8_t f = ch->alpn[0], l = ch->alpn[ch->alpn_len - 1];
	if (alnum(f) && alnum(l)) {
		out[0] = (char)f;
		out[1] = (char)l;
		return;
	}
	static const char d[] = "0123456789abcdef";
	out[0] = d[f >> 4];
	out[1] = d[l & 15];
}

int bst_ja4_compute(const bst_client_hello *ch, char transport, char out[40])
{
	if ((transport != 't' && transport != 'q') || (ch->ciphers_len & 1) != 0 ||
	    ch->ciphers_len / 2 > MAX_CIPHERS || ch->next > BST_JA4_MAX_EXT)
		return -1;
	uint16_t cs[MAX_CIPHERS];
	size_t nc = 0;
	for (size_t i = 0; i < ch->ciphers_len; i += 2) {
		uint16_t v = be16(ch->ciphers + i);
		if (!grease(v))
			cs[nc++] = v;
	}
	qsort(cs, nc, sizeof cs[0], cmp16);
	uint16_t es[BST_JA4_MAX_EXT];
	size_t ne = 0, nsorted = 0;
	for (size_t i = 0; i < ch->next; i++) {
		if (grease(ch->exts[i]))
			continue;
		ne++;
		if (ch->exts[i] != EXT_SNI && ch->exts[i] != EXT_ALPN)
			es[nsorted++] = ch->exts[i];
	}
	qsort(es, nsorted, sizeof es[0], cmp16);

	char hc[13], he[13];
	hasher h = { EVP_MD_CTX_new(), true };
	if (h.c == NULL)
		return -1;
	int rc = 0;
	if (nc == 0) {
		memcpy(hc, "000000000000", 13);
	} else if (EVP_DigestInit_ex(h.c, EVP_sha256(), NULL) != 1) {
		rc = -1;
	} else {
		for (size_t i = 0; i < nc; i++)
			put(&h, cs[i]);
		rc = finish(&h, hc);
	}
	if (rc == 0 && nsorted == 0 && !ch->has_sigalgs) {
		memcpy(he, "000000000000", 13);
	} else if (rc == 0) {
		h.first = true;
		if (EVP_DigestInit_ex(h.c, EVP_sha256(), NULL) != 1) {
			rc = -1;
		} else {
			for (size_t i = 0; i < nsorted; i++)
				put(&h, es[i]);
			if (ch->has_sigalgs) {
				EVP_DigestUpdate(h.c, "_", 1);
				h.first = true;
				for (size_t i = 0; i < ch->sigalgs_len; i += 2) {
					uint16_t v = be16(ch->sigalgs + i);
					if (!grease(v))
						put(&h, v);
				}
			}
			rc = finish(&h, he);
		}
	}
	EVP_MD_CTX_free(h.c);
	if (rc != 0)
		return -1;
	char alpn[3];
	alpn_chars(ch, alpn);
	snprintf(out, 40, "%c%s%c%02u%02u%s_%s_%s", transport, version_name(ch), ch->has_sni ? 'd' : 'i',
		 (unsigned)(nc > 99 ? 99 : nc), (unsigned)(ne > 99 ? 99 : ne), alpn, hc, he);
	return 0;
}

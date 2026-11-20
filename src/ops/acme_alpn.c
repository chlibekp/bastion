/* TLS-ALPN-01 (RFC 8737): the job puts a self-signed certificate per name in the shared region;
 * a worker installs it on a handshake whose ClientHello offers acme-tls/1 and nothing else for
 * that SNI name, and ALPN then selects acme-tls/1 (tls/ctx.c). No other handshake ever sees it. */
#include "ops/acme_priv.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

int bst_acme_alpn_put(const char *name, const char *cert_pem, size_t cert_len, const char *key_pem,
		      size_t key_len)
{
	bst_acme_region *r = bst_acme_region_;
	size_t nl = strlen(name);
	if (r == NULL || nl == 0 || nl >= BST_ACME_NAME_MAX || cert_len + key_len > BST_ACME_PEM_MAX)
		return -1;
	bst_acme_alpn_ent *slot = NULL;
	for (size_t i = 0; i < BST_ACME_ALPN_CERTS; i++) {
		bst_acme_alpn_ent *e = &r->alpn[i];
		uint32_t s = atomic_load_explicit(&e->seq, memory_order_relaxed);
		if (s != 0 && e->nlen == nl && strncasecmp(e->name, name, nl) == 0) {
			slot = e;
			break;
		}
		if (slot == NULL && s == 0)
			slot = e;
	}
	if (slot == NULL)
		return -1;
	uint32_t w = bst_acme_write_begin(&slot->seq);
	memcpy(slot->name, name, nl);
	slot->nlen = (uint16_t)nl;
	memcpy(slot->pem, cert_pem, cert_len);
	memcpy(slot->pem + cert_len, key_pem, key_len);
	slot->clen = (uint16_t)cert_len;
	slot->klen = (uint16_t)key_len;
	bst_acme_write_end(&slot->seq, w);
	return 0;
}

void bst_acme_alpn_remove(const char *name)
{
	bst_acme_region *r = bst_acme_region_;
	size_t nl = strlen(name);
	if (r == NULL)
		return;
	for (size_t i = 0; i < BST_ACME_ALPN_CERTS; i++) {
		bst_acme_alpn_ent *e = &r->alpn[i];
		if (atomic_load_explicit(&e->seq, memory_order_relaxed) == 0 || e->nlen != nl ||
		    strncasecmp(e->name, name, nl) != 0)
			continue;
		(void)bst_acme_write_begin(&e->seq);
		memset(e->pem, 0, sizeof e->pem); /* the key of a challenge certificate, but a key */
		e->nlen = e->clen = e->klen = 0;
		atomic_store_explicit(&e->seq, 0, memory_order_release);
	}
}

/* The ClientHello's ALPN list is exactly acme-tls/1. */
static bool offers_only_acme(SSL *ssl)
{
	const unsigned char *p;
	size_t l;
	static const unsigned char want[] = "\x00\x0b\x0a" "acme-tls/1";
	if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &p, &l))
		return false;
	return l == sizeof want - 1 && memcmp(p, want, l) == 0;
}

bool bst_acme_alpn_hello(void *sslp, const char *name, size_t nl)
{
	SSL *ssl = sslp;
	bst_acme_region *r = bst_acme_region_;
	if (r == NULL || nl == 0 || nl >= BST_ACME_NAME_MAX || !offers_only_acme(ssl))
		return false;
	static char pem[BST_ACME_PEM_MAX];
	for (size_t i = 0; i < BST_ACME_ALPN_CERTS; i++) {
		bst_acme_alpn_ent *e = &r->alpn[i];
		uint32_t s1 = atomic_load_explicit(&e->seq, memory_order_acquire);
		if (s1 == 0 || (s1 & 1u))
			continue;
		uint16_t enl = e->nlen, cl = e->clen, kl = e->klen;
		if (enl != nl || (size_t)cl + kl > sizeof pem || cl == 0 || kl == 0)
			continue;
		char en[BST_ACME_NAME_MAX];
		memcpy(en, e->name, enl);
		memcpy(pem, e->pem, (size_t)cl + kl);
		atomic_thread_fence(memory_order_acquire);
		if (atomic_load_explicit(&e->seq, memory_order_relaxed) != s1 || strncasecmp(en, name, nl) != 0)
			continue;
		BIO *cb = BIO_new_mem_buf(pem, cl), *kb = BIO_new_mem_buf(pem + cl, kl);
		X509 *x = cb != NULL ? PEM_read_bio_X509(cb, NULL, NULL, NULL) : NULL;
		EVP_PKEY *k = kb != NULL ? PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL) : NULL;
		bool ok = x != NULL && k != NULL && SSL_use_certificate(ssl, x) == 1 &&
			  SSL_use_PrivateKey(ssl, k) == 1;
		BIO_free(cb);
		BIO_free(kb);
		X509_free(x);
		EVP_PKEY_free(k);
		OPENSSL_cleanse(pem, (size_t)cl + kl);
		ERR_clear_error();
		return ok;
	}
	return false;
}

void bst_acme_alpn_digest(bst_str keyauth, unsigned char out[32])
{
	unsigned int n = 0;
	(void)EVP_Digest(keyauth.p, keyauth.len, out, &n, EVP_sha256(), NULL);
}

int bst_acme_alpn_cert(const char *name, const unsigned char digest[32], char **cert_pem,
		       size_t *cert_len, char **key_pem, size_t *key_len)
{
	EVP_PKEY *k = bst_acme_keygen(BST_ACME_KEY_P256);
	if (k == NULL)
		return -1;
	*key_pem = bst_acme_key_pem(k, key_len);
	char *plain = NULL;
	size_t plen = 0;
	const char *names[1] = { name };
	plain = bst_acme_selfsigned(k, names, 1, 7, &plen);
	int rc = -1;
	X509 *x = NULL;
	BIO *in = NULL, *out = NULL;
	ASN1_OBJECT *obj = NULL;
	ASN1_OCTET_STRING *val = NULL;
	X509_EXTENSION *ext = NULL;
	if (*key_pem == NULL || plain == NULL)
		goto out;
	in = BIO_new_mem_buf(plain, (int)plen);
	x = in != NULL ? PEM_read_bio_X509(in, NULL, NULL, NULL) : NULL;
	/* id-pe-acmeIdentifier, critical, its value the DER OCTET STRING of the digest */
	unsigned char der[34] = { 0x04, 0x20 };
	memcpy(der + 2, digest, 32);
	obj = OBJ_txt2obj("1.3.6.1.5.5.7.1.31", 1);
	val = ASN1_OCTET_STRING_new();
	if (x == NULL || obj == NULL || val == NULL || ASN1_OCTET_STRING_set(val, der, sizeof der) != 1)
		goto out;
	ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 1, val);
	if (ext == NULL || X509_add_ext(x, ext, -1) != 1 || X509_sign(x, k, EVP_sha256()) <= 0)
		goto out;
	out = BIO_new(BIO_s_mem());
	if (out == NULL || PEM_write_bio_X509(out, x) != 1)
		goto out;
	char *p;
	long bl = BIO_get_mem_data(out, &p);
	*cert_pem = malloc((size_t)bl + 1);
	if (*cert_pem == NULL)
		goto out;
	memcpy(*cert_pem, p, (size_t)bl);
	(*cert_pem)[bl] = '\0';
	*cert_len = (size_t)bl;
	rc = 0;
out:
	if (rc != 0) {
		free(*key_pem);
		*key_pem = NULL;
	}
	X509_EXTENSION_free(ext);
	ASN1_OCTET_STRING_free(val);
	ASN1_OBJECT_free(obj);
	BIO_free(in);
	BIO_free(out);
	X509_free(x);
	free(plain);
	EVP_PKEY_free(k);
	ERR_clear_error();
	return rc;
}

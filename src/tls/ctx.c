/* See ctx.h. */
#include "tls/ctx.h"

#include "tls/ktls.h"
#include "tls/ocsp.h"
#include "tls/sni.h"
#include "tls/early.h"
#include "tls/tickets.h"

#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ALPN: h2 first (when the server has a listener with the `http2` flag: arg is that flag, stored
 * in the pointer), then http/1.1; the connection starts the protocol the handshake chose
 * (http/h1/conn.c). A client that offers nothing we speak gets no ALPN, which is allowed. */
static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
		       const unsigned char *in, unsigned inlen, void *arg)
{
	static const unsigned char both[] = "\x02h2\x08http/1.1";
	static const unsigned char h1[] = "\x08http/1.1";
	(void)ssl;
	const unsigned char *ours = arg != NULL ? both : h1;
	size_t n = arg != NULL ? sizeof both - 1 : sizeof h1 - 1;
	if (SSL_select_next_proto((unsigned char **)(uintptr_t)out, outlen, ours, (unsigned)n, in, inlen) !=
	    OPENSSL_NPN_NEGOTIATED)
		return SSL_TLSEXT_ERR_NOACK;
	return SSL_TLSEXT_ERR_OK;
}

static pthread_once_t init_once = PTHREAD_ONCE_INIT;

static void do_init(void)
{
	/* No config file, no engines: both would open files, and a worker is not allowed to. The
	 * default provider is compiled in, so the first fetch needs no file either. */
	OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG | OPENSSL_INIT_LOAD_SSL_STRINGS |
				 OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
			 NULL);
}

void bst_tls_init(void)
{
	pthread_once(&init_once, do_init);
}

/* The newest reason on the OpenSSL error queue, as text, then clears the queue. It names a
 * reason code ("key values mismatch", "no start line"), never data read from a file. */
static const char *reason(char *buf, size_t cap)
{
	unsigned long e = ERR_peek_last_error();
	const char *r = e != 0 ? ERR_reason_error_string(e) : NULL;
	snprintf(buf, cap, "%s", r != NULL ? r : "unknown error");
	ERR_clear_error();
	return buf;
}

static int readable(const char *path, const char *what, bst_err *err)
{
	if (access(path, R_OK) != 0) {
		bst_err_set(err, "%s %s: %s", what, path, strerror(errno));
		return -1;
	}
	return 0;
}

static int key_type(SSL_CTX *ctx)
{
	X509 *x = SSL_CTX_get0_certificate(ctx);
	EVP_PKEY *k = x != NULL ? X509_get0_pubkey(x) : NULL;
	return k != NULL ? EVP_PKEY_get_base_id(k) : 0;
}

static int load_one(SSL_CTX *ctx, const bst_cfg_tls_cert *c, int *seen, size_t *nseen, bst_err *err)
{
	char why[96];
	if (readable(c->crt, "tls_cert certificate", err) != 0 ||
	    readable(c->key, "tls_cert key", err) != 0)
		return -1;
	if (SSL_CTX_use_certificate_chain_file(ctx, c->crt) != 1) {
		bst_err_set(err, "tls_cert %s %s: cannot load the certificate: %s", c->crt, c->key,
			    reason(why, sizeof why));
		return -1;
	}
	int type = key_type(ctx);
	for (size_t i = 0; i < *nseen; i++)
		if (seen[i] == type) {
			bst_err_set(err, "tls_cert %s %s: a second certificate of the same key type: a "
					 "server serves one RSA and one ECDSA certificate", c->crt, c->key);
			return -1;
		}
	if (SSL_CTX_use_PrivateKey_file(ctx, c->key, SSL_FILETYPE_PEM) != 1) {
		unsigned long e = ERR_peek_last_error();
		bool mismatch = ERR_GET_REASON(e) == X509_R_KEY_VALUES_MISMATCH ||
				ERR_GET_REASON(e) == X509_R_KEY_TYPE_MISMATCH;
		if (mismatch)
			ERR_clear_error();
		if (mismatch)
			bst_err_set(err, "tls_cert: private key %s does not match certificate %s", c->key,
				    c->crt);
		else
			bst_err_set(err, "tls_cert %s %s: cannot load the private key: %s", c->crt, c->key,
				    reason(why, sizeof why));
		return -1;
	}
	if (SSL_CTX_check_private_key(ctx) != 1) {
		ERR_clear_error();
		bst_err_set(err, "tls_cert: private key %s does not match certificate %s", c->key, c->crt);
		return -1;
	}
	seen[(*nseen)++] = type;
	return 0;
}

void bst_tls_sid_context(const bst_cfg_tls *t, unsigned char out[BST_TLS_SID_LEN])
{
	EVP_MD_CTX *m = EVP_MD_CTX_new();
	unsigned len = 0;
	unsigned char d[EVP_MAX_MD_SIZE];
	memset(out, 0, BST_TLS_SID_LEN);
	if (m == NULL || EVP_DigestInit_ex(m, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(m);
		return;
	}
#define FEED(p, n) (void)EVP_DigestUpdate(m, (p), (n))
#define FEED_STR(s) do { const char *s_ = (s) ? (s) : ""; FEED(s_, strlen(s_) + 1); } while (0)
	FEED_STR(t->profile != NULL ? t->profile->name : "");
	for (size_t i = 0; i < t->ncerts; i++) {
		FEED_STR(t->certs[i].crt);
		FEED_STR(t->certs[i].key);
	}
	FEED(&t->client_auth, sizeof t->client_auth);
	FEED(&t->verify_depth, sizeof t->verify_depth);
	FEED_STR(t->client_ca);
	FEED_STR(t->client_crl);
	(void)EVP_DigestFinal_ex(m, d, &len);
	EVP_MD_CTX_free(m);
	memcpy(out, d, len < BST_TLS_SID_LEN ? len : BST_TLS_SID_LEN);
}

/* Client certificates: the CA file is the only trust anchor, an optional CRL is checked along the
 * whole chain, and the depth is bounded. `required` fails a handshake without a certificate;
 * `optional` accepts none but still rejects one that does not verify (auth_mtls decides per
 * location, tls/conn.c). */
static int client_auth(SSL_CTX *ctx, const bst_cfg_tls *t, bst_err *err)
{
	if (SSL_CTX_load_verify_locations(ctx, t->client_ca, NULL) != 1) {
		bst_err_set(err, "tls_client_ca %s: cannot load the certificate authority file", t->client_ca);
		return -1;
	}
	STACK_OF(X509_NAME) *names = SSL_load_client_CA_file(t->client_ca);
	if (names == NULL) {
		bst_err_set(err, "tls_client_ca %s: no certificate in it", t->client_ca);
		return -1;
	}
	SSL_CTX_set_client_CA_list(ctx, names);
	if (t->client_crl != NULL) {
		X509_STORE *st = SSL_CTX_get_cert_store(ctx);
		FILE *f = fopen(t->client_crl, "re");
		X509_CRL *crl = f != NULL ? PEM_read_X509_CRL(f, NULL, NULL, NULL) : NULL;
		if (f != NULL)
			fclose(f);
		if (crl == NULL || X509_STORE_add_crl(st, crl) != 1) {
			X509_CRL_free(crl);
			bst_err_set(err, "tls_client_crl %s: cannot load the revocation list", t->client_crl);
			return -1;
		}
		X509_CRL_free(crl);
		X509_STORE_set_flags(st, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	}
	int mode = SSL_VERIFY_PEER;
	if (t->client_auth == BST_CLIENT_AUTH_REQUIRED)
		mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	SSL_CTX_set_verify(ctx, mode, NULL);
	SSL_CTX_set_verify_depth(ctx, (int)t->verify_depth);
	return 0;
}

SSL_CTX *bst_tls_ctx_build(const bst_cfg_tls *t, bst_err *err)
{
	bst_tls_init();
	const bst_cfg_tls_profile *p = t->profile;
	if (p == NULL || t->ncerts == 0) {
		bst_err_set(err, "tls: no certificate");
		return NULL;
	}
	ERR_clear_error();
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL) {
		bst_err_set(err, "tls: cannot create a context");
		ERR_clear_error();
		return NULL;
	}
	char why[96];
	uint64_t opts = SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION;
	if (p->prefer_server_ciphers)
		opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;
	SSL_CTX_set_options(ctx, opts);
	SSL_CTX_set_alpn_select_cb(ctx, alpn_select, t->http2 ? (void *)(uintptr_t)1 : NULL);
	bst_tls_ktls_ctx(ctx, t->profile);
	bst_tls_sni_ctx(ctx);
	if (p->tickets)
		bst_tickets_ctx(ctx);
	if (p->ocsp_stapling || t->nocsp_files > 0)
		bst_ocsp_ctx(ctx);
	SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ENABLE_PARTIAL_WRITE |
				      SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	if (SSL_CTX_set_min_proto_version(ctx, p->min_version) != 1 ||
	    SSL_CTX_set_max_proto_version(ctx, p->max_version) != 1) {
		bst_err_set(err, "tls_profile %s: cannot set the protocol versions", p->name);
		goto fail;
	}
	if (SSL_CTX_set1_groups_list(ctx, p->groups) != 1) {
		bst_err_set(err, "tls_profile %s: groups \"%s\": %s", p->name, p->groups,
			    reason(why, sizeof why));
		goto fail;
	}
	if (SSL_CTX_set_cipher_list(ctx, p->ciphers_tls12) != 1) {
		bst_err_set(err, "tls_profile %s: ciphers_tls12 \"%s\": %s", p->name, p->ciphers_tls12,
			    reason(why, sizeof why));
		goto fail;
	}
	if (SSL_CTX_set_ciphersuites(ctx, p->ciphersuites_tls13) != 1) {
		bst_err_set(err, "tls_profile %s: ciphersuites_tls13 \"%s\": %s", p->name,
			    p->ciphersuites_tls13, reason(why, sizeof why));
		goto fail;
	}
	if (p->sigalgs != NULL && SSL_CTX_set1_sigalgs_list(ctx, p->sigalgs) != 1) {
		bst_err_set(err, "tls_profile %s: sigalgs \"%s\": %s", p->name, p->sigalgs,
			    reason(why, sizeof why));
		goto fail;
	}
	/* Resumption is by ticket (tls/tickets.c): a per-process cache cannot serve a connection
	 * that lands on another worker. */
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_dh_auto(ctx, p->dh_none ? 0 : 1);
	if (!p->tickets) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
		SSL_CTX_set_num_tickets(ctx, 0);
	}
	unsigned char sid[BST_TLS_SID_LEN];
	bst_tls_sid_context(t, sid);
	if (SSL_CTX_set_session_id_context(ctx, sid, sizeof sid) != 1) {
		bst_err_set(err, "tls: cannot set the session id context");
		goto fail;
	}
	if (t->client_auth != BST_CLIENT_AUTH_OFF && client_auth(ctx, t, err) != 0)
		goto fail;
	if (p->early_data && !p->tickets) {
		bst_err_set(err, "early_data needs tickets on: a 0-RTT connection resumes a ticket");
		goto fail;
	}
	bst_early_ctx(ctx, p, t->client_auth != BST_CLIENT_AUTH_OFF);
	int seen[8];
	size_t nseen = 0;
	for (size_t i = 0; i < t->ncerts && nseen < sizeof seen / sizeof seen[0]; i++)
		if (load_one(ctx, &t->certs[i], seen, &nseen, err) != 0)
			goto fail;
	ERR_clear_error();
	return ctx;
fail:
	ERR_clear_error();
	SSL_CTX_free(ctx);
	return NULL;
}

int bst_tls_cert_validity(const char *crt)
{
	FILE *f = fopen(crt, "re");
	if (f == NULL)
		return -2;
	X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
	fclose(f);
	ERR_clear_error();
	if (x == NULL)
		return -2;
	int r = 0;
	if (X509_cmp_current_time(X509_get0_notAfter(x)) < 0)
		r = -1;
	else if (X509_cmp_current_time(X509_get0_notBefore(x)) > 0)
		r = 1;
	X509_free(x);
	return r;
}

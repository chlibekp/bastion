/* The TLS context builder and its directives: hardened defaults, certificate loading errors,
 * dual certificates. Handshakes run over memory BIOs against the context the config compiler
 * built, so the whole path from directive to SSL_CTX is covered. */
#include "tls/ctx.h"
#include "tls_support.h"

#include <openssl/x509.h>
#include <strings.h>

#define SRV(extra)                                                                      \
	"server { listen 127.0.0.1:8443 tls; " extra " }\n"
#define ECDSA "tls_cert " CERTS "/ecdsa-chain.crt " CERTS "/ecdsa.key;"
#define RSA "tls_cert " CERTS "/rsa.crt " CERTS "/rsa.key;"

static SSL_CTX *ctx_of(bst_config *c)
{
	return c->global.servers[0]->tls.ctx;
}

static bool err_has(const char *needle)
{
	return strstr(TLS_E.msg, needle) != NULL;
}

static bool warned(bst_config *c, const char *needle)
{
	size_t n;
	const bst_cfg_warning *w = bst_config_warnings(c, &n);
	for (size_t i = 0; i < n; i++)
		if (strstr(w[i].msg, needle) != NULL)
			return true;
	return false;
}

TEST(defaults)
{
	bst_config *c = tls_compile(SRV(ECDSA));
	ASSERT(c != NULL);
	SSL_CTX *ctx = ctx_of(c);
	ASSERT(ctx != NULL);
	ASSERT_EQ(SSL_CTX_get_min_proto_version(ctx), TLS1_2_VERSION);
	ASSERT_EQ(SSL_CTX_get_max_proto_version(ctx), TLS1_3_VERSION);
	/* TLS 1.0 and 1.1 are refused. */
	SSL *cs, *ss;
	SSL_CTX *old = client_ctx(NULL, NULL, NULL, TLS1_1_VERSION);
	ASSERT(!tls_handshake(ctx, old, "localhost", &cs, &ss));
	SSL_free(cs), SSL_free(ss), SSL_CTX_free(old);
	/* TLS 1.2 offers ECDHE with AEAD only. */
	STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ctx);
	int n12 = 0;
	for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
		const SSL_CIPHER *ci = sk_SSL_CIPHER_value(ciphers, i);
		if (strcmp(SSL_CIPHER_get_version(ci), "TLSv1.3") == 0)
			continue;
		const char *name = SSL_CIPHER_get_name(ci);
		n12++;
		ASSERT(strncmp(name, "ECDHE-", 6) == 0);
		ASSERT(strstr(name, "GCM") != NULL || strstr(name, "CHACHA20") != NULL);
	}
	ASSERT(n12 > 0);
	/* A TLS 1.2 client that offers only CBC and static RSA finds no common cipher. */
	SSL_CTX *weak = client_ctx("AES128-SHA:ECDHE-ECDSA-AES128-SHA", NULL, NULL, TLS1_2_VERSION);
	ASSERT(!tls_handshake(ctx, weak, "localhost", &cs, &ss));
	SSL_free(cs), SSL_free(ss), SSL_CTX_free(weak);
	bst_config_free(c);
}

TEST(group_order)
{
	bst_config *c = tls_compile(SRV(ECDSA));
	ASSERT(c != NULL);
	SSL *cs, *ss;
	SSL_CTX *both = client_ctx(NULL, NULL, "*X25519:*X25519MLKEM768", TLS1_3_VERSION);
	ASSERT(tls_handshake(ctx_of(c), both, "localhost", &cs, &ss));
	/* The server's order wins: the hybrid is first, so it is chosen although the client listed it second. */
	ASSERT_STR(SSL_group_to_name(ss, (int)SSL_get_negotiated_group(ss)), "X25519MLKEM768");
	SSL_free(cs), SSL_free(ss), SSL_CTX_free(both);
	SSL_CTX *classic = client_ctx(NULL, NULL, "X25519:P-256", TLS1_3_VERSION);
	ASSERT(tls_handshake(ctx_of(c), classic, "localhost", &cs, &ss));
	ASSERT(strcasecmp(SSL_group_to_name(ss, (int)SSL_get_negotiated_group(ss)), "X25519") == 0);
	SSL_free(cs), SSL_free(ss), SSL_CTX_free(classic);
	bst_config_free(c);
}

TEST(compression_off)
{
	bst_config *c = tls_compile(SRV(ECDSA));
	ASSERT(c != NULL);
	ASSERT(SSL_CTX_get_options(ctx_of(c)) & SSL_OP_NO_COMPRESSION);
	bst_config_free(c);
}

TEST(renegotiation_off)
{
	bst_config *c = tls_compile(SRV(ECDSA));
	ASSERT(c != NULL);
	ASSERT(SSL_CTX_get_options(ctx_of(c)) & SSL_OP_NO_RENEGOTIATION);
	bst_config_free(c);
	/* and the directive cannot turn it on */
	ASSERT(tls_compile("tls_profile p { renegotiation on; }\n" SRV(ECDSA)) == NULL);
}

TEST(key_mismatch)
{
	bst_config *c = tls_compile(SRV("tls_cert " CERTS "/ecdsa.crt " CERTS "/rsa.key;"));
	ASSERT(c == NULL);
	ASSERT(err_has("ecdsa.crt") && err_has("rsa.key"));
	ASSERT(err_has("does not match"));
	/* the same pair, key of another curve */
	ASSERT(tls_compile(SRV("tls_cert " CERTS "/ecdsa.crt " CERTS "/other.key;")) == NULL);
	ASSERT(err_has("ecdsa.crt") && err_has("other.key"));
}

TEST(expired_cert_warns)
{
	bst_config *c = tls_compile(SRV("tls_cert " CERTS "/expired.crt " CERTS "/expired.key;"));
	ASSERT(c != NULL); /* a warning, not an error: -t exits 0 */
	ASSERT(warned(c, "expired"));
	bst_config_free(c);
	c = tls_compile(SRV(ECDSA));
	ASSERT(c != NULL && !warned(c, "expired"));
	bst_config_free(c);
}

TEST(unreadable_key)
{
	FILE *f = fopen(CERTS "/garbage.key", "w");
	ASSERT(f != NULL);
	fputs("SECRET-KEY-MATERIAL-0123456789\nnot a pem file\n", f);
	fclose(f);
	ASSERT(tls_compile(SRV("tls_cert " CERTS "/ecdsa.crt " CERTS "/garbage.key;")) == NULL);
	ASSERT(err_has("garbage.key"));
	ASSERT(!err_has("SECRET-KEY-MATERIAL")); /* the error never carries key contents */
	ASSERT(tls_compile(SRV("tls_cert " CERTS "/ecdsa.crt " CERTS "/nonexistent.key;")) == NULL);
	ASSERT(err_has("nonexistent.key") && err_has("No such file"));
	ASSERT(tls_compile(SRV("tls_cert " CERTS "/nonexistent.crt " CERTS "/ecdsa.key;")) == NULL);
	ASSERT(err_has("nonexistent.crt"));
}

static int server_key_type(SSL *client)
{
	X509 *x = SSL_get0_peer_certificate(client);
	return x != NULL ? EVP_PKEY_get_base_id(X509_get0_pubkey(x)) : 0;
}

TEST(dual_cert)
{
	bst_config *c = tls_compile(SRV(ECDSA " " RSA));
	ASSERT(c != NULL);
	SSL *cs, *ss;
	SSL_CTX *rsa12 = client_ctx("ECDHE-RSA-AES128-GCM-SHA256", NULL, NULL, TLS1_2_VERSION);
	ASSERT(tls_handshake(ctx_of(c), rsa12, "localhost", &cs, &ss));
	ASSERT_EQ(server_key_type(cs), EVP_PKEY_RSA);
	SSL_free(cs), SSL_free(ss), SSL_CTX_free(rsa12);
	SSL_CTX *ec12 = client_ctx("ECDHE-ECDSA-AES128-GCM-SHA256", NULL, NULL, TLS1_2_VERSION);
	ASSERT(tls_handshake(ctx_of(c), ec12, "localhost", &cs, &ss));
	ASSERT_EQ(server_key_type(cs), EVP_PKEY_EC);
	SSL_free(cs), SSL_free(ss), SSL_CTX_free(ec12);
	/* TLS 1.3: the client's signature algorithms decide */
	SSL_CTX *rsa13 = client_ctx(NULL, NULL, NULL, TLS1_3_VERSION);
	SSL_CTX_set1_sigalgs_list(rsa13, "rsa_pss_rsae_sha256");
	ASSERT(tls_handshake(ctx_of(c), rsa13, "localhost", &cs, &ss));
	ASSERT_EQ(server_key_type(cs), EVP_PKEY_RSA);
	SSL_free(cs), SSL_free(ss), SSL_CTX_free(rsa13);
	bst_config_free(c);
	/* two certificates of one key type are refused: the second would silently replace the first */
	ASSERT(tls_compile(SRV(ECDSA " tls_cert " CERTS "/site-a.crt " CERTS "/site-a.key;")) == NULL);
	ASSERT(err_has("same key type"));
}

TEST(profile_directives)
{
	bst_config *c = tls_compile("tls_profile modern { versions 1.3; handshake_timeout 3s; "
				    "ktls tx+rx require; tickets off; early_data on; "
				    "early_data_methods GET HEAD OPTIONS; early_data_max_size 4k; }\n"
				    "server { listen 127.0.0.1:8443 tls; tls_profile modern; " ECDSA " }\n");
	ASSERT(c != NULL);
	const bst_cfg_tls_profile *p = c->global.servers[0]->tls.profile;
	ASSERT_STR(p->name, "modern");
	ASSERT_EQ(p->min_version, TLS1_3_VERSION);
	ASSERT_EQ(p->max_version, TLS1_3_VERSION);
	ASSERT_EQ(p->handshake_timeout_ms, 3000);
	ASSERT_EQ(p->ktls, BST_KTLS_TXRX);
	ASSERT(p->ktls_require);
	ASSERT(!p->tickets);
	ASSERT(p->early_data);
	ASSERT_EQ(p->early_max_size, 4096);
	ASSERT_EQ(SSL_CTX_get_min_proto_version(ctx_of(c)), TLS1_3_VERSION);
	/* a TLS 1.3 only server refuses a TLS 1.2 client */
	SSL *cs, *ss;
	SSL_CTX *c12 = client_ctx(NULL, NULL, NULL, TLS1_2_VERSION);
	ASSERT(!tls_handshake(ctx_of(c), c12, "localhost", &cs, &ss));
	SSL_free(cs), SSL_free(ss), SSL_CTX_free(c12);
	bst_config_free(c);
}

TEST(implicit_profile_equals_empty_block)
{
	bst_config *a = tls_compile("tls_profile p { }\nserver { listen 127.0.0.1:8443 tls; tls_profile p; " ECDSA " }\n");
	ASSERT(a != NULL);
	const bst_cfg_tls_profile *named = a->global.servers[0]->tls.profile, *dflt = &a->global.tls_default;
	ASSERT_EQ(named->min_version, dflt->min_version);
	ASSERT_EQ(named->max_version, dflt->max_version);
	ASSERT_STR(named->groups, dflt->groups);
	ASSERT_STR(named->ciphers_tls12, dflt->ciphers_tls12);
	ASSERT_STR(named->ciphersuites_tls13, dflt->ciphersuites_tls13);
	ASSERT_STR(named->sigalgs, dflt->sigalgs);
	ASSERT_EQ(named->prefer_server_ciphers, dflt->prefer_server_ciphers);
	ASSERT_EQ(named->dh_none, dflt->dh_none);
	ASSERT_EQ(named->handshake_timeout_ms, dflt->handshake_timeout_ms);
	ASSERT_EQ(named->ktls, dflt->ktls);
	ASSERT_EQ(named->tickets, dflt->tickets);
	ASSERT_EQ(named->tickets_rotate_ms, dflt->tickets_rotate_ms);
	ASSERT_EQ(named->tickets_keep, dflt->tickets_keep);
	ASSERT_EQ(named->ocsp_stapling, dflt->ocsp_stapling);
	ASSERT_EQ(named->early_data, dflt->early_data);
	ASSERT_EQ(named->early_methods, dflt->early_methods);
	ASSERT_EQ(named->early_max_size, dflt->early_max_size);
	bst_config_free(a);
}

TEST(config_errors)
{
	ASSERT(tls_compile("server { listen 127.0.0.1:8443 tls; }\n") == NULL);
	ASSERT(err_has("tls_cert"));
	ASSERT(tls_compile("server { listen 127.0.0.1:8443 tls; tls_profile nope; " ECDSA " }\n") == NULL);
	ASSERT(err_has("undefined tls_profile"));
	ASSERT(tls_compile("tls_profile p { }\ntls_profile p { }\nserver { listen 127.0.0.1:8443 tls; " ECDSA " }\n") == NULL);
	ASSERT(err_has("duplicate tls_profile"));
	ASSERT(tls_compile("server { listen 127.0.0.1:8443 tls; " ECDSA " }\nserver { listen 127.0.0.1:8443; name x; }\n") == NULL);
	ASSERT(err_has("either TLS or plain"));
	ASSERT(tls_compile("tls_profile p { groups \"no-such-group\"; }\nserver { listen 127.0.0.1:8443 tls; tls_profile p; " ECDSA " }\n") == NULL);
	ASSERT(err_has("groups"));
	bst_config *c = tls_compile("server { listen 127.0.0.1:8443; " ECDSA " }\n");
	ASSERT(c != NULL && warned(c, "no `tls` listener"));
	bst_config_free(c);
}

TAP_MAIN()

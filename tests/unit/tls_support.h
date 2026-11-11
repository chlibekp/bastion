/* Shared by the TLS unit tests: certificates from tests/fixtures/certs/gen.sh, a config compiler
 * and an in-memory handshake between a server context and a client. */
#ifndef BST_TEST_TLS_SUPPORT_H
#define BST_TEST_TLS_SUPPORT_H

#include "config/compile.h"
#include "config/parser.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "tap.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>

#define CERTS "build/test-certs"

/* OpenSSL's allocator must be mimalloc before the first OpenSSL call, as in main. */
static void __attribute__((constructor(101))) tls_support_init(void)
{
	(void)bst_alloc_init();
	if (system("tests/fixtures/certs/gen.sh " CERTS " >/dev/null 2>&1") != 0)
		fputs("# cannot generate test certificates\n", stderr);
}

static bst_arena *TLS_LAST;
static bst_err TLS_E;

/* The AST stays alive until the next call, so TLS_E.file (which points into it) stays readable. */
static bst_config *tls_compile(const char *text)
{
	bst_arena_free(TLS_LAST);
	TLS_LAST = bst_arena_new(1 << 16);
	memset(&TLS_E, 0, sizeof TLS_E);
	bst_ast *ast = bst_cfg_parse_string(text, strlen(text), "t.conf", NULL, TLS_LAST, &TLS_E);
	bst_config *c = ast ? bst_cfg_compile(ast, &TLS_E) : NULL;
	if (c == NULL && getenv("TLS_DEBUG"))
		fprintf(stderr, "# compile failed: %s\n", TLS_E.msg);
	return c;
}

static SSL_CTX *client_ctx(const char *ciphers12, const char *suites13, const char *groups, int maxver)
{
	SSL_CTX *c = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_security_level(c, 0);
	SSL_CTX_set_min_proto_version(c, 0);
	SSL_CTX_set_max_proto_version(c, maxver);
	if (ciphers12)
		SSL_CTX_set_cipher_list(c, ciphers12);
	if (suites13)
		SSL_CTX_set_ciphersuites(c, suites13);
	if (groups)
		SSL_CTX_set1_groups_list(c, groups);
	return c;
}

/* Runs both ends over a memory BIO pair until both finish or one fails. 1 when the handshake
 * completed on both sides; *cs and *ss are the connections (the caller frees them). */
static int tls_handshake(SSL_CTX *sctx, SSL_CTX *cctx, const char *sni, SSL **cs, SSL **ss)
{
	SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
	BIO *b1, *b2;
	BIO_new_bio_pair(&b1, 0, &b2, 0);
	SSL_set_bio(c, b1, b1);
	SSL_set_bio(s, b2, b2);
	if (sni != NULL)
		SSL_set_tlsext_host_name(c, sni);
	int cd = 0, sd = 0;
	for (int i = 0; i < 64 && !(cd && sd); i++) {
		if (!cd) {
			int r = SSL_connect(c);
			if (r == 1)
				cd = 1;
			else if (SSL_get_error(c, r) != SSL_ERROR_WANT_READ && SSL_get_error(c, r) != SSL_ERROR_WANT_WRITE)
				break;
		}
		if (!sd) {
			int r = SSL_accept(s);
			if (r == 1)
				sd = 1;
			else if (SSL_get_error(s, r) != SSL_ERROR_WANT_READ && SSL_get_error(s, r) != SSL_ERROR_WANT_WRITE)
				break;
		}
	}
	ERR_clear_error();
	*cs = c;
	*ss = s;
	return cd && sd;
}

#endif

#include "tls/sni.h"

#include <string.h>

static int sni_idx = -1;

int bst_tls_sni_parse(const unsigned char *ext, size_t len, char *out, size_t cap)
{
	if (cap < BST_SNI_MAX + 1)
		return -1;
	if (len < 2)
		return -1;
	size_t list = (size_t)ext[0] << 8 | ext[1];
	if (list != len - 2)
		return -1;
	const unsigned char *p = ext + 2, *end = ext + len;
	while (p < end) {
		if (end - p < 3)
			return -1;
		unsigned type = p[0];
		size_t n = (size_t)p[1] << 8 | p[2];
		p += 3;
		if ((size_t)(end - p) < n)
			return -1;
		if (type != 0) { /* a name type we do not know: skip it */
			p += n;
			continue;
		}
		if (n > BST_SNI_MAX + 1)
			return -1;
		size_t m = n;
		if (m > 0 && p[m - 1] == '.')
			m--; /* one trailing dot */
		if (m == 0 || m > BST_SNI_MAX || p[m - 1] == '.')
			return -1;
		for (size_t i = 0; i < m; i++) {
			unsigned char ch = p[i];
			bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				  (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
			if (!ok || (ch == '.' && (i == 0 || p[i - 1] == '.')))
				return -1;
			out[i] = (char)(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);
		}
		out[m] = '\0';
		return (int)m;
	}
	return 0;
}

static int client_hello(SSL *ssl, int *al, void *arg)
{
	(void)arg;
	bst_tls_sni *st = SSL_get_ex_data(ssl, sni_idx);
	if (st == NULL || st->set == NULL)
		return SSL_CLIENT_HELLO_SUCCESS;
	const bst_cfg_server *dflt = bst_vhost_default(st->set);
	const unsigned char *ext;
	size_t elen;
	char name[BST_SNI_MAX + 1];
	int n = 0;
	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &ext, &elen)) {
		n = bst_tls_sni_parse(ext, elen, name, sizeof name);
		if (n < 0) {
			*al = SSL_AD_ILLEGAL_PARAMETER;
			return SSL_CLIENT_HELLO_ERROR;
		}
	}
	SSL_CTX *target;
	if (n == 0) {
		if (dflt->tls.sni_required) {
			*al = SSL_AD_MISSING_EXTENSION;
			return SSL_CLIENT_HELLO_ERROR;
		}
		target = dflt->tls.default_ctx != NULL ? dflt->tls.default_ctx : dflt->tls.ctx;
	} else {
		bool matched = false;
		const bst_cfg_server *srv = bst_vhost_lookup(st->set, (bst_str){ name, (uint32_t)n }, &matched);
		if (matched) {
			st->server = srv;
			target = srv->tls.ctx;
		} else if (dflt->tls.sni_reject) {
			*al = SSL_AD_UNRECOGNIZED_NAME;
			return SSL_CLIENT_HELLO_ERROR;
		} else {
			target = dflt->tls.default_ctx != NULL ? dflt->tls.default_ctx : dflt->tls.ctx;
		}
	}
	st->chosen = st->server != NULL ? st->server : dflt;
	if (target != NULL && target != SSL_get_SSL_CTX(ssl)) {
		(void)SSL_set_SSL_CTX(ssl, target);
		/* SSL_set_SSL_CTX keeps the verify settings the SSL was created with (the first
		 * context's): the chosen server's client-certificate policy must be applied by hand. */
		SSL_set_verify(ssl, SSL_CTX_get_verify_mode(target), NULL);
		SSL_set_verify_depth(ssl, SSL_CTX_get_verify_depth(target));
	}
	return SSL_CLIENT_HELLO_SUCCESS;
}

void bst_tls_sni_ctx(SSL_CTX *ctx)
{
	if (sni_idx < 0)
		sni_idx = SSL_get_ex_new_index(0, "bst_tls_sni", NULL, NULL, NULL);
	SSL_CTX_set_client_hello_cb(ctx, client_hello, NULL);
}

void bst_tls_sni_attach(SSL *ssl, bst_tls_sni *st)
{
	(void)SSL_set_ex_data(ssl, sni_idx, st);
}

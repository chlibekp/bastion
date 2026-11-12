/* SNI: which server's certificate a handshake gets, and the host mismatch policy.
 *
 * The client hello callback runs once per handshake, before any certificate is chosen. It reads
 * the server_name extension, normalises the name (case, one trailing dot), picks the virtual server
 * the same way a Host header would (route/vhost.h), and moves the connection to that server's
 * SSL_CTX. No SNI, or a name no server has, gets the default server's tls_default_cert (or its own
 * certificates) unless `sni_required` or `sni_mismatch reject` say the handshake fails
 * (handshake_failure and unrecognized_name alerts). The server chosen is remembered so a request
 * whose Host names another server can be answered 421 (`host_sni_mismatch`). */
#ifndef BST_TLS_SNI_H
#define BST_TLS_SNI_H

#include "config/compile.h"
#include "route/vhost.h"

#include <openssl/ssl.h>

#define BST_SNI_MAX 253 /* a DNS name */

typedef struct bst_tls_sni {
	const bst_listener_set *set;
	const bst_cfg_server *server; /* the server the SNI named, NULL when none did */
	const bst_cfg_server *chosen; /* the server whose context the handshake used */
	char ja4[40];		      /* the client's JA4, "" unless the default server says tls_ja4 on */
	bool quic;		      /* a QUIC handshake: switches to the servers' QUIC contexts */
} bst_tls_sni;

/* Parses the server_name extension body (RFC 6066) into out (NUL-terminated, lower-cased, at most
 * BST_SNI_MAX characters, a trailing dot removed). Returns the length, 0 when the extension holds no
 * host_name, -1 when it is malformed, too long or holds a character a host name cannot have. */
int bst_tls_sni_parse(const unsigned char *ext, size_t len, char *out, size_t cap);

/* Installs the client hello callback on a context being built. Master, before any worker. */
void bst_tls_sni_ctx(SSL_CTX *ctx);

/* The server whose context the handshake of ssl uses (NULL before the client hello was read). */
const bst_cfg_server *bst_tls_sni_chosen(SSL *ssl);

/* Attaches the per-connection state (which must outlive the SSL) to ssl. */
void bst_tls_sni_attach(SSL *ssl, bst_tls_sni *st);

#endif

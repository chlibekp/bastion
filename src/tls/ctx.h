/* TLS context builder: one SSL_CTX per server, from its certificates and its tls_profile.
 *
 * Hardened defaults (architecture section 6): TLS 1.2 minimum, ECDHE with AEAD ciphers only,
 * groups X25519MLKEM768:X25519:P-256, no compression, no renegotiation, server cipher preference.
 * Every one of them is a tls_profile directive (config/tls_directives.c); nothing here is a
 * constant an operator might need to change.
 *
 * Keys. A context is built in master, before any sandbox: it reads the certificate and key files,
 * so a mismatch or an unreadable file is a load error naming both files (never the key's bytes),
 * and `bastion -t` finds it. Workers inherit the finished contexts through fork and never open a
 * key file. */
#ifndef BST_TLS_CTX_H
#define BST_TLS_CTX_H

#include "config/compile.h"
#include "core/err.h"

#include <openssl/ssl.h>

/* Initialises OpenSSL once for this process without reading any configuration file or loading
 * any engine or provider module: a sandboxed worker must never open one lazily. Idempotent. */
void bst_tls_init(void);

/* The context for t (its profile must be resolved). NULL with err set. A certificate is
 * accepted in PEM form with its chain after the leaf. */
SSL_CTX *bst_tls_ctx_build(const bst_cfg_tls *t, bst_err *err);

/* The context of t's `http3` listeners (spikes/quic/README.md finding 8): the same certificates,
 * groups, ticket key callback and early data policy, but ALPN h3 only, TLS 1.3 only, max_early_data
 * 0xffffffff when 0-RTT is on, no SNI switch, and a session id context of its own so TCP and QUIC
 * tickets never cross. ngtcp2_crypto_ossl configures each SSL made from it. NULL with err set. */
SSL_CTX *bst_tls_ctx_build_quic(const bst_cfg_tls *t, bst_err *err);

/* Why a certificate would warn at load: -1 expired, 1 not yet valid, 0 fine, -2 unreadable. */
int bst_tls_cert_validity(const char *crt);

/* The session id context a server's contexts carry: resumption never crosses servers whose
 * client-authentication setup differs. 32 bytes. */
#define BST_TLS_SID_LEN 32
void bst_tls_sid_context(const bst_cfg_tls *t, unsigned char out[BST_TLS_SID_LEN]);

#endif

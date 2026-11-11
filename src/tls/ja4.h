/* JA4: the TLS client fingerprint of FoxIO (https://github.com/FoxIO-LLC/ja4, technical_details/JA4.md),
 * and only that one: the separately licensed JA4+ methods are not implemented (docs/third-party.md).
 *
 *   <t|q><version><d|i><ciphers><extensions><alpn>_<cipher hash>_<extension hash>
 *
 * The fingerprint is a pure function of the ClientHello (ja4.c). The hello is read once, in the
 * client hello callback (tls/sni.c), and only on a listener whose server says `tls_ja4 on`: a
 * server that never logs or routes on $ja4 pays nothing. */
#ifndef BST_TLS_JA4_H
#define BST_TLS_JA4_H

#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_JA4_LEN 36		/* characters, without the NUL */
#define BST_JA4_MAX_EXT 512	/* extensions kept: a hello with more is refused, not truncated */

/* What the fingerprint needs from a ClientHello. The pointers refer to the buffer it was read from. */
typedef struct bst_client_hello {
	uint16_t legacy_version;
	const uint8_t *ciphers; /* 2 bytes each */
	size_t ciphers_len;
	uint16_t exts[BST_JA4_MAX_EXT]; /* extension types in wire order */
	size_t next;
	bool has_sni;
	bool has_alpn;
	const uint8_t *alpn;	/* the first protocol name of the ALPN extension */
	size_t alpn_len;
	bool has_sigalgs;
	const uint8_t *sigalgs; /* signature_algorithms list, 2 bytes each */
	size_t sigalgs_len;
	bool has_versions;
	const uint8_t *versions; /* supported_versions list, 2 bytes each */
	size_t versions_len;
} bst_client_hello;

/* Reads a ClientHello handshake message (type, 24-bit length, body) from msg. 0, or -1 when it is
 * truncated, malformed, not a ClientHello or has more than BST_JA4_MAX_EXT extensions. */
int bst_client_hello_parse(const uint8_t *msg, size_t len, bst_client_hello *ch);

/* Fills ch from the hello the callback of ssl is running for. 0, or -1. */
int bst_client_hello_from_ssl(SSL *ssl, bst_client_hello *ch);

/* Writes the fingerprint and a NUL into out; transport is 't' (TCP) or 'q' (QUIC). 0, or -1 for a
 * transport it does not know or a malformed list. GREASE values never count. */
int bst_ja4_compute(const bst_client_hello *ch, char transport, char out[40]);

#endif

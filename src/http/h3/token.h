/* QUIC address validation tokens and stateless reset tokens (RFC 9000 sections 8.1 and 10.3).
 *
 * A Retry token proves that a client receives at the address it claims: it is AEAD-sealed under the
 * token secret, binds the client's address and port, the QUIC version, the Retry's source connection
 * ID and the client's original destination connection ID, and expires after BST_TOKEN_RETRY_TTL_MS.
 * A regular token (sent in NEW_TOKEN after a handshake) binds the address only and lets a returning
 * client skip the Retry round trip for BST_TOKEN_REGULAR_TTL_MS. Both are ngtcp2_crypto's formats.
 *
 * The secrets are the same in every worker (tls/tickets.h, the `tickets` shared region): a token
 * issued by one worker validates in another, and any worker can reset a connection another holds.
 * Timestamps are CLOCK_MONOTONIC nanoseconds, one clock for the whole machine. */
#ifndef BST_H3_TOKEN_H
#define BST_H3_TOKEN_H

#include "core/addr.h"

#include <ngtcp2/ngtcp2.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define BST_TOKEN_SECRET_LEN 32
#define BST_TOKEN_MAX 256		    /* room for either kind of token */
#define BST_TOKEN_RETRY_TTL_MS 10000u	    /* a Retry is answered within a round trip */
#define BST_TOKEN_REGULAR_TTL_MS 3600000u   /* NEW_TOKEN: a returning client within the hour */

/* The secrets this process uses (from the shared region, tls/tickets.h): token, then reset. */
typedef struct bst_quic_secrets {
	uint8_t token[BST_TOKEN_SECRET_LEN];
	uint8_t reset[BST_TOKEN_SECRET_LEN];
} bst_quic_secrets;

/* Fills ss from a; returns its length (0 for a family that is neither IPv4 nor IPv6). */
socklen_t bst_quic_sockaddr(const bst_sockaddr *a, struct sockaddr_storage *ss);

/* A Retry token for peer in out (BST_TOKEN_MAX bytes). Its length, or -1. */
ngtcp2_ssize bst_token_retry(uint8_t *out, const bst_quic_secrets *s, uint32_t version,
			     const bst_sockaddr *peer, const ngtcp2_cid *retry_scid,
			     const ngtcp2_cid *odcid, uint64_t now_ns);

/* Checks a Retry token that arrived in an Initial for dcid (the Retry's source ID) from peer.
 * 0 with *odcid set to the client's original destination ID; -1 when it was sealed for another
 * address, version or ID, has expired, or any byte was changed. */
int bst_token_retry_check(ngtcp2_cid *odcid, const uint8_t *tok, size_t len, const bst_quic_secrets *s,
			  uint32_t version, const bst_sockaddr *peer, const ngtcp2_cid *dcid,
			  uint64_t now_ns);

/* A NEW_TOKEN token for peer in out (BST_TOKEN_MAX bytes). Its length, or -1. */
ngtcp2_ssize bst_token_regular(uint8_t *out, const bst_quic_secrets *s, const bst_sockaddr *peer,
			       uint64_t now_ns);
/* 0 when tok is a regular token for peer that has not expired, else -1. */
int bst_token_regular_check(const uint8_t *tok, size_t len, const bst_quic_secrets *s,
			    const bst_sockaddr *peer, uint64_t now_ns);

/* The stateless reset token of cid (16 bytes). 0, or -1. */
int bst_token_reset(uint8_t out[NGTCP2_STATELESS_RESET_TOKENLEN], const bst_quic_secrets *s,
		    const ngtcp2_cid *cid);

#endif

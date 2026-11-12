/* Session ticket keys shared by every worker (architecture section 6).
 *
 * One memfd region, made by master before any fork and inherited by workers and the helper. It
 * holds the newest `keep` keys, newest first. The helper is the only writer (bst_tickets_rotate);
 * workers read through a seqlock that needs no lock a worker could be killed holding, and make
 * their own copy of the few keys they need. Nothing else holds key material: not a file the worker
 * reads, not the config, not a core dump (MADV_DONTDUMP) or swap (mlock where the limit allows).
 *
 * `tickets ... file=PATH` loads the keys from a file instead, for several instances that must
 * resume each other's tickets; the keys then never rotate on their own (the operator rewrites the
 * file and reloads). The file is read by master only, before sandboxing.
 *
 * Tickets are encrypted with AES-256-CBC and authenticated with HMAC-SHA256 under the key named in
 * the ticket (RFC 5077 section 4), through OpenSSL's ticket key callback. */
#ifndef BST_TLS_TICKETS_H
#define BST_TLS_TICKETS_H

#include "config/compile.h"
#include "core/err.h"

#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>

#define BST_TICKET_KEYS_MAX 16

typedef struct bst_ticket_key {
	unsigned char name[16], aes[32], hmac[32];
	uint64_t created_ms;
} bst_ticket_key;

/* Bytes of the shared region. */
size_t bst_tickets_size(void);

/* QUIC (http/h3/token.h): after the keys the region holds 64 random bytes, the Retry and address
 * token secret then the stateless reset secret, the same in every worker so any worker validates a
 * token another issued and resets a connection another holds. Master makes the region whenever a
 * listener has `http3`, with or without tickets, and calls this once before any fork. 0, or -1
 * when no randomness is available. */
#define BST_QUIC_SECRETS_LEN 64
int bst_tickets_quic_init(void *region);
/* This process's copy of the secrets (inherited from master). 0, or -1 when none were made. */
int bst_tickets_quic_secrets(unsigned char out[BST_QUIC_SECRETS_LEN]);

/* Writes the first key (random, or the keys of file when non-NULL) into a fresh region. */
int bst_tickets_init(void *region, unsigned keep, const char *file, bst_err *err);

/* Replaces the ring with exactly these keys (newest first) under the sequence lock. Master and
 * tests; rotation is the only caller in a running server. */
void bst_tickets_publish(void *region, const bst_ticket_key *keys, unsigned n);

/* Adds a new newest key and drops those beyond keep. The only writer: the helper. 0, or -1 when
 * no randomness is available. */
int bst_tickets_rotate(void *region, unsigned keep);

/* A consistent copy of the keys, newest first; returns how many (at most max). Safe against a
 * concurrent rotate: never a torn key. */
unsigned bst_tickets_snapshot(const void *region, bst_ticket_key *out, unsigned max);

/* Marks the region non-dumpable and tries to lock it. Master, once. Returns 0, or 1 when mlock was
 * refused (the keys may reach swap: the caller warns). */
int bst_tickets_protect(void *region);

/* The region this process serves tickets from (master, before fork; inherited). */
void bst_tickets_use(void *region);

/* Installs the ticket callback on a context being built. */
void bst_tickets_ctx(SSL_CTX *ctx);

/* The tickets policy of the configuration: false when no TLS server enables tickets. */
bool bst_tickets_policy(const bst_config *cfg, uint64_t *rotate_ms, unsigned *keep, const char **file);

#endif

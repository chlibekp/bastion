/* TLS 1.3 0-RTT (early data), restricted (architecture section 6).
 *
 * Early data is replayable: nothing in the protocol stops an attacker who records the first flight
 * from sending it again. Bastion accepts it only when all of these hold, and each is checked when the
 * client hello names the ticket, before a byte of early data is read:
 *   - the server's tls_profile says `early_data on` and the server asks for no client certificate;
 *   - the ticket has not been used for early data before, by any worker, within
 *     `early_data_window` (a table of ticket fingerprints in shared memory, below);
 *   - OpenSSL's own freshness check on the age the client reports passed.
 * What is served from it is limited to the methods of `early_data_methods` (h1/conn.c answers
 * 425 Too Early to the rest), and `bst_req.early_data` tells handlers.
 *
 * OpenSSL's built-in anti-replay needs its server session cache, which is incompatible with tickets
 * shared by all workers (tls/tickets.h), so it is turned off (SSL_OP_NO_ANTI_REPLAY) and this table
 * replaces it. OpenSSL rejects a ticket whose age differs from the server's own count by more than
 * ten seconds, so a flight replayed after the window is stale as well as unknown.
 *
 * The table is one memfd region of BST_EARLY_SLOTS atomic words, made by master before any fork. A
 * word holds a 40-bit fingerprint (the start of SHA-256 over the ticket's secret) and the second it
 * expires at (24 bits, wrapping): one compare-and-swap claims a slot, so no lock exists that a killed
 * worker could hold. A table too full to claim a slot refuses early data (the safe direction), and
 * so does a fingerprint collision. */
#ifndef BST_TLS_EARLY_H
#define BST_TLS_EARLY_H

#include "config/compile.h"

#include <openssl/ssl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define BST_EARLY_SLOTS 16384 /* a power of two; 128 KiB */
#define BST_EARLY_PROBE 8

/* Bytes of the shared region. */
size_t bst_early_size(void);

/* True when some TLS profile of the configuration enables early data. */
bool bst_early_wanted(const bst_config *cfg);

/* The region this process claims tickets in (master, before fork; inherited). NULL: no early data. */
void bst_early_use(void *region);
bool bst_early_active(void);

/* Claims a ticket for early data in a table: true the first time within window_s seconds of now_s,
 * false for a ticket seen before or when the neighbourhood of its slot is full. Safe against
 * concurrent claims of the same fingerprint from any number of processes: exactly one gets true.
 * Exposed for tests; bst_early_allow is the one caller of the running server. */
bool bst_early_claim(void *region, uint64_t fingerprint, uint32_t now_s, unsigned window_s);

/* SSL_CTX_set_allow_early_data_cb callback: the policy above for the connection's chosen server. */
int bst_early_allow(SSL *ssl, void *arg);

/* Makes ctx accept early data per the profile (max size, no OpenSSL anti-replay, the callback), or
 * says none for sure when the profile or the server's client-auth policy does not allow it. */
void bst_early_ctx(SSL_CTX *ctx, const bst_cfg_tls_profile *p, bool mtls);

#endif

/* HTTP Basic authentication (RFC 7617) against Argon2id hashes in PHC string format.
 *
 *   auth_basic_file   lines `user:$argon2id$v=19$m=<KiB>,t=<n>,p=<n>$<salt>$<hash>` (salt and
 *                     hash in unpadded standard base64; `#` comments and blank lines skipped),
 *                     parsed by the master at load into memory marked MADV_DONTDUMP. An
 *                     unreadable or malformed file fails the load: a protected location never
 *                     silently opens.
 *   verification      Argon2id (OpenSSL EVP_KDF, 3.2+) on the aio pool, at most
 *                     auth_max_concurrent per worker; past it the answer is 503 with
 *                     Retry-After, so a flood can not take the event loop or other locations
 *                     down. An unknown user hashes against a dummy entry with the same cost,
 *                     so timing does not tell users apart. Results compare in constant time.
 *   cache             successful checks are remembered for auth_cache_ttl under an HMAC of the
 *                     credentials with a per-worker random key (never the plaintext), so a
 *                     client sending the same header does not cost a hash each request.
 *
 * The Authorization header value is never logged. */
#ifndef BST_AUTH_BASIC_H
#define BST_AUTH_BASIC_H

#include "core/str.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_PHC_SALT_MAX 64
#define BST_PHC_HASH_MAX 128

typedef struct bst_phc {
	uint32_t m_kib, t, p;
	uint8_t salt[BST_PHC_SALT_MAX];
	size_t salt_len;
	uint8_t hash[BST_PHC_HASH_MAX];
	size_t hash_len;
} bst_phc;

/* Parses an Argon2id PHC string. 0, or -1 when it is not one Bastion accepts: another
 * algorithm or version, parameters out of range (m up to 1 GiB, t 1..64, p 1..64), salt of
 * 8..64 bytes, hash of 16..128 bytes, bad base64. */
int bst_phc_parse(bst_str s, bst_phc *out);
/* Below the OWASP floor (m >= 19 MiB with t >= 2): the loader warns. */
bool bst_phc_weak(const bst_phc *h);
/* Formats a PHC string into out (NUL-terminated). Its length, or 0 when cap is too small. */
size_t bst_phc_format(const bst_phc *h, char *out, size_t cap);

/* Argon2id of pass with h's parameters and salt, h->hash_len bytes into out. 0 or -1. */
int bst_argon2id(const char *pass, size_t plen, const bst_phc *h, uint8_t *out);

/* Decodes an Authorization value of the Basic scheme. 0 with user and password set (pointing
 * into buf, NUL-terminated); -1 for another scheme, bad base64, no colon, a control byte in
 * the user, or more than cap bytes. */
int bst_basic_decode(bst_str value, char *buf, size_t cap, bst_str *user, bst_str *pass);

/* Loads an auth_basic_file into memory marked MADV_DONTDUMP. NULL with why set on failure;
 * *weak counts entries below the OWASP floor. Freed with bst_basic_users_free (wiped first). */
typedef struct bst_basic_users bst_basic_users;
const bst_basic_users *bst_basic_users_load(const char *path, unsigned *weak, char *why,
					    size_t whycap);
void bst_basic_users_free(void *users);
/* Checks user and pass against u synchronously (one Argon2id hash, an unknown user hashes the
 * dummy entry): for the helper's metrics endpoint, which has no aio pool. */
bool bst_basic_users_check(const bst_basic_users *u, bst_str user, bst_str pass);

/* `bastion passwd [-m KiB] [-t n] [-p n] [user]`: reads the password from the terminal
 * (twice, without echo) or a line of stdin, prints the auth_basic_file line. Exit code. */
int bst_passwd_main(int argc, char **argv);

#endif

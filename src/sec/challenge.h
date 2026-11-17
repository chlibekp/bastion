/* A very simple proof-of-work challenge with a replaceable page (Phase 12, Task 5; see
 * docs/challenge.md for the contract a custom page relies on).
 *
 *   1. A request without a valid pass cookie gets 403, Cache-Control: no-store, and the HTML page
 *      (or a plain-text 403 when it does not accept text/html).
 *   2. The page carries a token "expiry.iphash.mac" and a difficulty in leading zero bits.
 *   3. The browser finds a nonce with SHA-256(token "." nonce) starting with that many zero bits
 *      and posts token, nonce and redirect to /.bastion/challenge.
 *   4. Bastion checks the MAC, the expiry, the client's IP prefix and the hash, sets the cookie
 *      "<expiry>.<mac>" and redirects (303) to the original path, a local path only.
 *   5. Later requests verify the cookie's MAC. Nothing is stored on the server.
 *
 * MACs are HMAC-SHA-256 under a per-generation secret derived from a random key in shared memory
 * (made by master before the first fork): generation g = now / rotate_s. A token or pass is valid
 * under the current generation or the one before it, so the secret rotates with one generation of
 * overlap and nothing has to be written after start. Both are bound to the client's /prefix4 or
 * /prefix6 network (24 and 56 by default), so a cookie lifted to another network is refused. All
 * comparisons are constant time. Times are wall-clock seconds. */
#ifndef BST_SEC_CHALLENGE_H
#define BST_SEC_CHALLENGE_H

#include "config/compile.h"
#include "core/addr.h"
#include "core/str.h"
#include "http/stream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_CHALLENGE_PATH "/.bastion/challenge"
#define BST_CHALLENGE_KEY_LEN 32
#define BST_CHALLENGE_TOKEN_MAX 96
#define BST_CHALLENGE_PASS_MAX 64

/* Master, before any fork: the shared key (zeroed memory of BST_CHALLENGE_KEY_LEN bytes) is filled
 * with randomness and used. 0, or -1 without randomness. */
int bst_challenge_setup(void *mem);
/* Uses key (a test, or a process that already has the memory). */
void bst_challenge_use_key(const uint8_t *key);

/* A token for ip at now (seconds) into out; its length, 0 when cap is too small. */
size_t bst_challenge_issue(const bst_challenge_cfg *c, const bst_ip *ip, uint64_t now, char *out, size_t cap);
/* Does nonce solve token for ip at now: a genuine, unexpired token of ip's prefix whose hash has
 * the configured leading zero bits? */
bool bst_challenge_verify_pow(const bst_challenge_cfg *c, bst_str token, bst_str nonce, const bst_ip *ip,
			      uint64_t now);
/* The pass cookie value for ip at now into out; its length. */
size_t bst_challenge_pass(const bst_challenge_cfg *c, const bst_ip *ip, uint64_t now, char *out, size_t cap);
bool bst_challenge_cookie_valid(const bst_challenge_cfg *c, bst_str cookie, const bst_ip *ip, uint64_t now);
/* True when the 32-byte hash starts with bits zero bits. */
bool bst_challenge_zero_bits(const uint8_t *hash, unsigned bits);

/* The wall clock in seconds. */
uint64_t bst_challenge_now(void);

/* Does the challenge apply to this request now: mode on, or auto under attack, or forced (a waf
 * `action challenge`)? */
bool bst_challenge_active(const bst_stream *s, bool force);
/* Request side, called by sec/sec.c with the client address set: the verify endpoint, a valid
 * pass, an allowlisted client, or the challenge. True: the request was taken over (answered,
 * or its body is being read); false: it passes on to the remaining checks. */
bool bst_challenge_check(bst_stream *s, bool force);
/* Is the request for the verify endpoint (BST_CHALLENGE_PATH)? */
bool bst_challenge_is_verify(const bst_stream *s);

/* Loads a challenge_page file into the config arena: the text, or NULL with why set. warn is set
 * when the page lacks the {{bastion_challenge}} placeholder. */
const char *bst_challenge_load_page(const char *path, bst_arena *a, size_t *len, bool *warn, char *why, size_t cap);

#endif

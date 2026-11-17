/* Request rate limits shared by every worker (Phase 12, Task 1; architecture section 7).
 *
 * A `limit_zone` is a table of slots in shared memory, one per client key. Each slot holds the
 * key's tag and its GCRA theoretical arrival time (TAT), both 64-bit atomics: a check is one
 * compare-and-swap on the TAT, with no lock, so the rate holds across all workers at once.
 *
 * GCRA: with emission interval T = period / count and a burst of B requests, the limit L is B*T.
 * A request at `now` is let in when max(TAT, now) + T - now <= L, and the TAT moves to
 * max(TAT, now) + T. A fresh key therefore gets exactly B requests at once, then one every T.
 * `mode delay` admits up to another B requests by delaying each until it conforms; past that,
 * or in `mode reject`, the request is refused with Retry-After.
 *
 * The key is hashed with keyed SipHash (a random key per zone made at load), so a client can
 * not aim keys at one slot. Lookup probes at most BST_LIMIT_PROBE slots; when none matches and
 * none is free, the least recently due of them is taken over (LRU-ish): a full table never
 * crashes, never probes further, and at worst forgets a quiet key. A TAT far beyond anything a
 * real sequence of checks can produce (a clock that went backwards, a slot left by a crashed
 * writer) is clamped, so no key is ever locked out for good. */
#ifndef BST_SEC_LIMIT_H
#define BST_SEC_LIMIT_H

#include "config/compile.h"
#include "config/values.h"
#include "core/addr.h"
#include "core/str.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define BST_LIMIT_PROBE 8

typedef struct bst_limit_slot {
	_Atomic uint64_t tag; /* 0: free */
	_Atomic uint64_t tat; /* nanoseconds on the monotonic clock */
} bst_limit_slot;

struct bst_tpl;

typedef struct bst_limit_zone {
	const char *name;
	bst_cfg_loc loc;
	/* Config. */
	const struct bst_tpl *key;  /* `key`; NULL or key_is_addr: the client address */
	bool key_is_addr;	    /* `key $remote_addr` (the default): keyed by address and prefix */
	bst_rate rate;
	bool rate_set;
	uint64_t burst;		    /* `rate ... burst=`, at least 1 */
	uint32_t size;		    /* slots, a power of two */
	bool delay;		    /* mode delay */
	unsigned status;	    /* the status of a refusal, 429 by default */
	unsigned ipv6_prefix;	    /* IPv6 addresses are keyed by this prefix, /64 by default */
	bool dry_run;		    /* count and log, never refuse */
	/* `escalate after= window= block=` (sec/escalate.h); after 0: off. */
	unsigned esc_after;
	uint64_t esc_window_us, esc_block_us;
	/* Runtime, set by bst_limit_zone_attach. */
	uint64_t t_ns, l_ns;	    /* emission interval and limit (burst * T) */
	uint8_t sipkey[16];
	bst_limit_slot *slots;
} bst_limit_zone;

/* `limit <zone>`: the name as written, resolved to the zone by a post hook. */
typedef struct bst_limit_ref {
	const char *name;
	bst_cfg_loc loc;
	bst_limit_zone *zone;
} bst_limit_ref;

typedef enum bst_limit_verdict { BST_LIMIT_ALLOW = 0, BST_LIMIT_DELAY, BST_LIMIT_REJECT } bst_limit_verdict;

typedef struct bst_limit_result {
	bst_limit_verdict verdict;
	uint64_t delay_us;	 /* DELAY: how long to hold the request */
	uint64_t retry_after_us; /* REJECT: when a request would be let in again */
	uint64_t remaining;	 /* requests left in the burst after this one (RateLimit) */
} bst_limit_result;

/* Bytes of shared memory a zone needs. */
size_t bst_limit_zone_bytes(const bst_limit_zone *z);
/* Points the zone at its slot memory (zeroed, bst_limit_zone_bytes long), computes T and L and
 * draws the hash key. 0, or -1 when there is no randomness. */
int bst_limit_zone_attach(bst_limit_zone *z, void *mem);

/* The hash of a client address: IPv4-mapped IPv6 is IPv4, IPv6 is cut to the zone's prefix. */
uint64_t bst_limit_key_ip(const bst_limit_zone *z, const bst_ip *ip);
uint64_t bst_limit_key_str(const bst_limit_zone *z, bst_str key);

/* One request of key (a hash from above) at now_us (monotonic). */
bst_limit_result bst_limit_check_hash(bst_limit_zone *z, uint64_t key, uint64_t now_us);
/* The same with a string key (bst_limit_key_str). */
bst_limit_result bst_limit_check(bst_limit_zone *z, bst_str key, uint64_t now_us);

/* The monotonic clock in microseconds (shared by every process). */
uint64_t bst_limit_now_us(void);

#endif

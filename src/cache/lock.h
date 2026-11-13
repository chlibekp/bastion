/* The stampede lock of a cache store: when many requests miss on one key at once, one of them
 * (in any worker) fetches it and the others wait for the stored object, so the upstream sees
 * one request instead of thousands.
 *
 * A fixed table in shared memory (`cache_index`), one 64-bit word per slot holding a tag of the
 * key, a "pass" flag and a deadline. Taking a lock is one CAS; a lock whose deadline passed is
 * free to take, so an owner that died (kill -9 mid-fill) holds it for lock_timeout at most and
 * nothing has to clean up after it. "pass" is what an owner leaves behind when the response
 * turned out not to be storable (private, Set-Cookie): waiters then fetch for themselves at once
 * instead of waiting, and never share that body. Tags are 23 bits: two keys with the same slot
 * and tag share a lock, which costs some waiting, never a wrong response. */
#ifndef BST_CACHE_LOCK_H
#define BST_CACHE_LOCK_H

#include "cache/store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bst_cachelock_table bst_cachelock_table;

size_t bst_cachelock_size(size_t nslots);
bst_cachelock_table *bst_cachelock_init(void *mem, size_t nslots);

typedef enum bst_lock_rc {
	BST_LOCK_WON = 0, /* this request fetches; release it with bst_cachelock_release */
	BST_LOCK_HELD,	  /* another request is fetching: wait for it */
	BST_LOCK_PASS,	  /* the last fetch was not storable: fetch without waiting */
	BST_LOCK_FULL,	  /* no slot: fetch without a lock */
} bst_lock_rc;

/* Tries to take the lock of k until deadline (monotonic ms, now_ms the clock). On WON, *slot is
 * the slot to release. */
bst_lock_rc bst_cachelock_try(bst_cachelock_table *t, const bst_key *k, unsigned *slot,
			      uint64_t deadline, uint64_t now_ms);
/* Gives the lock back. pass: until pass_until, others are told to fetch for themselves. Does
 * nothing when the lock is no longer ours (it expired and was taken). */
void bst_cachelock_release(bst_cachelock_table *t, const bst_key *k, unsigned slot,
			   uint64_t taken_deadline, bool pass, uint64_t pass_until);
/* True when the lock in slot has passed its deadline (or is free). */
bool bst_cachelock_expired(bst_cachelock_table *t, unsigned slot, uint64_t now_ms);

#endif

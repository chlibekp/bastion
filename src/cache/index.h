/* The shared index of a disk cache store: which objects exist, how big they are, when they were
 * filled and last used. One open-addressed table in shared memory (`cache_index`, made by master
 * before the fork), read and written by every worker and the helper without locks.
 *
 * A slot's state word holds a generation and one of EMPTY, BUSY (being written), LIVE or TOMB
 * (removed; reusable). Inserting claims an EMPTY or TOMB slot with a CAS, writes the fields and
 * publishes LIVE with release; a reader takes LIVE with acquire, copies the fields and checks the
 * state word again, so a slot reused meanwhile is noticed (the generation changed). Every field
 * is an atomic, so concurrent use is free of data races (TSan-clean).
 *
 * The index is a cache of the disk, never the other way round: an object the index lacks is a
 * miss (the startup scan adds what is on disk in the background), and an entry whose file is gone
 * is a miss too. last_access is written at most once a second per entry, relaxed, so a hot
 * object does not bounce its cache line between workers. Workers never delete files during
 * eviction; the helper does (eviction.c). */
#ifndef BST_CACHE_INDEX_H
#define BST_CACHE_INDEX_H

#include "cache/store.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bst_centry {
	bst_key key;
	uint64_t size;	      /* bytes on disk */
	int64_t stored_at_ms; /* when its fill began */
	int64_t req_time, resp_time; /* seconds; refreshed by a 304 revalidation */
	uint32_t last_access; /* seconds since the epoch */
	uint32_t uses;
} bst_centry;

typedef struct bst_cindex bst_cindex;

/* Bytes of shared memory for nslots slots. */
size_t bst_cindex_size(size_t nslots);
/* Lays out a zeroed region of bst_cindex_size(nslots) bytes. */
bst_cindex *bst_cindex_init(void *mem, size_t nslots);

/* A copy of the live entry for key: true when found. */
bool bst_cindex_lookup(bst_cindex *x, const bst_key *k, bst_centry *out);
/* Adds or replaces the entry for e->key (size, times, uses=1, last_access). False when the table
 * has no free slot within the probe limit (counted in full_count); the server goes on uncached. */
bool bst_cindex_insert(bst_cindex *x, const bst_centry *e);
/* Marks a use at now (seconds): written only when a second has passed since the last one.
 * Returns the use count after it, 0 when the key is not indexed. */
uint32_t bst_cindex_touch(bst_cindex *x, const bst_key *k, uint32_t now);
/* Refreshes the revalidation times of key. False when not indexed. */
bool bst_cindex_refresh(bst_cindex *x, const bst_key *k, int64_t req_time, int64_t resp_time);
/* Removes the entry for key; true when there was one. The file is not touched. */
bool bst_cindex_remove(bst_cindex *x, const bst_key *k);

/* The bytes and entries indexed, and failed inserts. */
uint64_t bst_cindex_bytes(const bst_cindex *x);
uint64_t bst_cindex_count(const bst_cindex *x);
uint64_t bst_cindex_full_count(const bst_cindex *x);
size_t bst_cindex_nslots(const bst_cindex *x);
/* Whether the helper's startup scan has finished (set by the helper). */
bool bst_cindex_scanned(const bst_cindex *x);
void bst_cindex_set_scanned(bst_cindex *x);

/* Slot i, when live: a copy of it. For the helper's sweeps. */
bool bst_cindex_slot(bst_cindex *x, size_t i, bst_centry *out);

/* ---- eviction.c: helper jobs ---- */

/* Startup scan state: walks <root>/ab/cd at `rate` files a call... see eviction.c. */
typedef struct bst_cache_scan {
	unsigned d1, d2;    /* the next directory: d1/d2 in hex */
	bool tmp_done;
	int64_t started;    /* temp files older than this (seconds) are leftovers */
	uint64_t files, bad, tmp_removed;
} bst_cache_scan;

/* Indexes up to max files (and removes leftover temp files and broken objects). Returns true
 * when the scan is complete. */
bool bst_cache_scan_step(bst_cindex *x, bst_store *st, bst_cache_scan *sc, unsigned max);

typedef struct bst_evict_cfg {
	uint64_t max_bytes;   /* `disk ... size=` */
	uint32_t inactive_s;  /* `inactive` */
	unsigned batch;	      /* `evict_batch`: removals per call at most */
	unsigned sample;      /* slots looked at per removal */
} bst_evict_cfg;

/* One eviction round: removes entries unused for inactive_s, then the least recently used of a
 * random sample until the bytes are under max_bytes or batch removals happened. Unlinks their
 * files. *cursor carries the inactive sweep's position between calls. Returns removals. */
unsigned bst_cache_evict(bst_cindex *x, bst_store *st, const bst_evict_cfg *c, uint32_t now,
			 size_t *cursor, uint64_t *rng);

#endif

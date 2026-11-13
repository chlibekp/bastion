/* Purging a cache store by URL, tag or host, or all of it, in O(1): nothing is searched or
 * deleted at purge time. A purge writes "purged at <now>" into a fixed table in shared memory,
 * at the slot of the purged thing's hash (and a store-wide time for `all`); a stored response is
 * valid only when its fill began after every purge that covers it (its URL, its host, each of its
 * tags, the whole store). The fill's start counts, not its end: a fill that began before a purge
 * and finished after it is never served.
 *
 * Collisions are safe: a slot keeps the latest time of every hash that maps to it, so two tags in
 * one slot can only cause extra misses, never keep a purged response alive. The table is saved to
 * <root>/purge.table by the helper (purge_save_interval) and read by master at start, so purges
 * survive a restart; a table saved with another size folds into the store-wide time (safe again:
 * more misses, never fewer). Tags come from the response's cache_tag_header (Cache-Tag). */
#ifndef BST_CACHE_PURGE_H
#define BST_CACHE_PURGE_H

#include "cache/store.h"
#include "core/str.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bst_purge_table bst_purge_table;

size_t bst_purge_size(size_t nslots);
bst_purge_table *bst_purge_init(void *mem, size_t nslots);

/* The hashes purges and stored responses agree on. */
uint64_t bst_purge_hash_tag(bst_str tag);
uint64_t bst_purge_hash_host(bst_str host); /* without a port, any letter case */
uint64_t bst_purge_hash_url(const bst_key *k);

/* Records a purge of hash h (or of everything) at when_ms (wall clock). */
void bst_purge_mark(bst_purge_table *t, uint64_t h, int64_t when_ms);
void bst_purge_mark_all(bst_purge_table *t, int64_t when_ms);
/* Counts purges: unchanged means nothing to save. */
uint64_t bst_purge_gen(const bst_purge_table *t);

/* Is a response filled from stored_at_ms on, with these URL keys (the key, and the base key of
 * a variant or NULL), host and tags, still valid? */
bool bst_purge_valid(const bst_purge_table *t, int64_t stored_at_ms, const bst_key *key,
		     const bst_key *base, uint64_t host_hash, const uint64_t *tags, uint32_t ntags);

/* Saves to / loads from <dirfd>/purge.table (the write goes through a temp file and a rename).
 * 0, or a negative errno; a missing file loads as an empty table. */
int bst_purge_save(const bst_purge_table *t, int dirfd);
int bst_purge_load(bst_purge_table *t, int dirfd);

/* Splits a tag header value (commas and spaces) into hashes, at most max. Returns the count. */
uint32_t bst_purge_tags(bst_str value, uint64_t *out, uint32_t max);

#endif

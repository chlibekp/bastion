/* The RAM tier: per worker, no locks, no shared pointers. A popular object may sit once in each
 * worker; that is the price of never sharing memory across processes (and of nothing to recover
 * after a crash). Objects are immutable once put and reference counted: a response being sent
 * holds a reference, so evicting an object never frees bytes still on their way to a client.
 *
 * Eviction is S3-FIFO (Yang et al., SOSP 2023), which resists scans: a new object enters a small
 * FIFO (a tenth of the bytes); it is promoted to the main FIFO only if it was used again while
 * there, else it leaves and its key is remembered in a ghost set, so an object that returns soon
 * goes straight to the main FIFO. The main FIFO gives every used object another round. A one-off
 * scan of many objects therefore passes through the small FIFO without touching the main one. */
#ifndef BST_CACHE_RAM_H
#define BST_CACHE_RAM_H

#include "cache/store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bst_robj {
	unsigned refs;
	bst_key key;
	bst_sobj_meta m;	  /* head, vary and tags point into this object's own memory */
	const unsigned char *body;
	size_t charge;		  /* bytes counted against the limit */
	/* the tier's own links */
	struct bst_robj *hnext;	  /* hash chain */
	struct bst_robj *qprev, *qnext;
	uint8_t freq;
	uint8_t queue;		  /* 0 none, 1 small, 2 main */
	uint64_t tagbuf[BST_STORE_MAX_TAGS];
} bst_robj;

typedef struct bst_ram bst_ram;

/* A tier of max_bytes keeping objects of at most max_object body bytes. NULL on exhaustion. */
bst_ram *bst_ram_new(size_t max_bytes, size_t max_object);
/* Drops the tier's references; objects still referenced live on until their last unref. */
void bst_ram_free(bst_ram *r);

/* A new reference to the object of key, or NULL. Counts as a use. */
bst_robj *bst_ram_get(bst_ram *r, const bst_key *k);
/* Stores a copy of the object (meta, then len body bytes), replacing one with the same key.
 * False when it is larger than max_object (it stays disk only) or memory ran out. */
bool bst_ram_put(bst_ram *r, const bst_key *k, const bst_sobj_meta *m, const void *body, size_t len);
/* Forgets key (a purge or invalidation). */
void bst_ram_remove(bst_ram *r, const bst_key *k);
void bst_robj_unref(bst_robj *o);

size_t bst_ram_bytes(const bst_ram *r);
size_t bst_ram_count(const bst_ram *r);
size_t bst_ram_max_object(const bst_ram *r);

#endif

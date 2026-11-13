/* The runtime of the cache stores: what master makes before the fork (the directory, the shared
 * index, the lock and purge tables) and the helper's background jobs on them. A worker reaches a
 * store through its config (bst_cfg_cache_store.rt). */
#ifndef BST_CACHE_CACHE_H
#define BST_CACHE_CACHE_H

#include "cache/index.h"
#include "cache/store.h"
#include "config/compile.h"
#include "core/err.h"
#include "io/loop.h"

#include <sys/types.h>

typedef struct bst_cache_rt {
	bst_cfg_cache_store *cfg;
	bst_store store;
	bst_cindex *idx;
	struct bst_cachelock_table *locks; /* cache/lock.h */
	struct bst_purge_table *purge;	   /* cache/purge.h */
	bool broken;			   /* the directory is unusable: serve uncached */
} bst_cache_rt;

/* In master, before any fork: for every store, makes its directory when missing (owned by uid
 * and gid when chown is set), opens it O_PATH and maps its shared tables. A directory that can
 * not be written is not fatal: the store is marked broken and requests go uncached, with a
 * warning. 0, or -1 with e set (out of memory, shared memory). */
int bst_cache_setup(bst_config *cfg, bool chown_dirs, uid_t uid, gid_t gid, bst_err *e);
/* The store directories, for the sandbox's write list: up to max into out; returns the count. */
size_t bst_cache_paths(const bst_config *cfg, const char **out, size_t max);
/* In the helper: the startup scan, then eviction once a second, for every store. */
void bst_cache_helper_start(bst_loop *l, const bst_config *cfg);

#endif

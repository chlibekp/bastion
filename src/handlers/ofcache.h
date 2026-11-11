/* An open file, and the per-worker cache of them (the `open_file_cache` directive). Loop thread
 * only: nothing here is atomic. The cache is pure data: callers pass the clock, so a test can
 * move time. */
#ifndef BST_HANDLERS_OFCACHE_H
#define BST_HANDLERS_OFCACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

/* A descriptor with what was learned about it when it was opened. Reference counted: a request
 * holds one while it sends, the cache holds one while an entry lives, and the descriptor closes
 * with the last. A file deleted or replaced on disk stays readable through a held reference. */
typedef struct bst_file {
	int fd;
	unsigned refs;
	off_t size;
	int64_t mtime_ns;
	uint64_t ino;
	mode_t mode; /* st_mode: S_ISREG, S_ISDIR, or something else the handler refuses */
	uid_t uid;
} bst_file;

/* Takes over fd (closed by the last unref). NULL on out of memory, fd not closed then. */
bst_file *bst_file_new(int fd, off_t size, int64_t mtime_ns, uint64_t ino, mode_t mode, uid_t uid);
bst_file *bst_file_ref(bst_file *f);
void bst_file_unref(bst_file *f); /* NULL is fine */

typedef struct bst_ofcache bst_ofcache;

/* max entries (at least 1), each trusted for ttl_ms. errors: bst_ofcache_put_err keeps entries. */
bst_ofcache *bst_ofcache_new(size_t max, uint64_t ttl_ms, bool errors);
void bst_ofcache_free(bst_ofcache *c); /* drops the cache's references */

/* A live entry for key: a new reference to the file (*err 0), or NULL with *err the cached errno
 * (a remembered failure), or NULL with *err 0 (not cached, or expired: it is dropped). A hit is the
 * most recently used. */
bst_file *bst_ofcache_get(bst_ofcache *c, const char *key, size_t len, uint64_t now_ms, int *err);
/* Remember f (a new reference is taken). The least recently used entry goes when the cache is full. */
void bst_ofcache_put(bst_ofcache *c, const char *key, size_t len, bst_file *f, uint64_t now_ms);
/* Remember a failure; a no-op unless the cache was made with errors. */
void bst_ofcache_put_err(bst_ofcache *c, const char *key, size_t len, int err, uint64_t now_ms);

size_t bst_ofcache_count(const bst_ofcache *c);

#endif

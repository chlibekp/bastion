/* A body held for later (`request_buffering`, `response_buffering`): the first bytes in memory up
 * to a limit (`spool_memory_limit`), the rest in an unnamed O_TMPFILE file below `temp_path`,
 * which the kernel removes with its last descriptor, so an abort, a crash or a kill leaves
 * nothing on disk.
 *
 * Writing appends (pwrite on the loop thread: a temp file's pages go to the page cache). Reading
 * the memory part is immediate; reading the file part runs pread on the aio pool
 * (bst_aio_submit), so the loop never waits on the disk. One process, one loop: no locks. */
#ifndef BST_PROXY_SPOOL_H
#define BST_PROXY_SPOOL_H

#include "core/buf.h"
#include "core/chain.h"
#include "proc/worker.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bst_spool bst_spool;

/* A new, empty spool of this worker keeping up to limit bytes in memory. NULL when out of memory. */
bst_spool *bst_spool_open(bst_worker *w, uint64_t limit);
/* Appends c, which must hold memory segments only, consuming it. 0, or a negative errno: -ENOSPC
 * or -EDQUOT for a full disk, -ENOENT when there is no temp_path to spill to, -ENOMEM, -EINVAL for
 * a file segment. After an error the spool keeps what it had before the failing segment. */
int bst_spool_write(bst_spool *sp, bst_chain *c);
int bst_spool_write_mem(bst_spool *sp, const void *data, size_t len);
uint64_t bst_spool_size(const bst_spool *sp);
/* Bytes that went to the file (0: never spilled). */
uint64_t bst_spool_spilled(const bst_spool *sp);

/* Reads up to max bytes from off. Returns 1 with *out set (a new buffer the caller owns, read from
 * memory) when the bytes are at hand, 0 when the read went to the aio pool (cb then runs on the
 * loop thread with the buffer, or NULL and a negative errno), or a negative errno. One read at a
 * time per spool. off at or past the end is -EINVAL. */
typedef void (*bst_spool_read_cb)(void *ud, bst_buf *b, int err);
int bst_spool_read(bst_spool *sp, uint64_t off, size_t max, bst_buf **out, bst_spool_read_cb cb,
		   void *ud);

/* Frees it and closes its file. A read still on the aio pool completes silently. NULL is ignored. */
void bst_spool_close(bst_spool *sp);

#endif

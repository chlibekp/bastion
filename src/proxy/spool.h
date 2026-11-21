/* A body held for later (`request_buffering`, `response_buffering`): the first bytes in memory up
 * to a limit (`spool_memory_limit`), the rest in an unnamed O_TMPFILE file below `temp_path`,
 * which the kernel removes with its last descriptor, so an abort, a crash or a kill leaves
 * nothing on disk.
 *
 * The loop never waits on the disk (NFR5). Writing past the memory part copies the bytes into a
 * write-behind queue that one job at a time on the aio pool (bst_aio_submit) appends to the file,
 * in order; opening the file is that job's too. Reading the memory part or bytes still queued is
 * immediate; reading the written file part runs pread on the aio pool. The caller bounds the
 * queue: bst_spool_pending says how much waits, bst_spool_flush calls back once it is written.
 * One process, one loop: no locks. */
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
/* Appends c, which must hold memory segments only, consuming it. 0, or a negative errno: -ENOENT
 * when there is no temp_path to spill to, -ENOMEM, -EINVAL for a file segment, or the failure of
 * an earlier write job (-ENOSPC or -EDQUOT for a full disk). A failed write job ends the spool
 * at its last good write: later writes, flushes and reads past that point return its error. */
int bst_spool_write(bst_spool *sp, bst_chain *c);
int bst_spool_write_mem(bst_spool *sp, const void *data, size_t len);
/* Bytes accepted (memory, file and queue). */
uint64_t bst_spool_size(const bst_spool *sp);
/* Bytes that went or go to the file (0: never spilled). */
uint64_t bst_spool_spilled(const bst_spool *sp);
/* Bytes accepted that the pool has not written yet. */
uint64_t bst_spool_pending(const bst_spool *sp);
/* 0 when nothing waits for the disk, a negative errno when a write failed, or 1: cb runs on the
 * loop thread once the queue is written (err 0) or a write failed (err < 0). One flush at a time;
 * a later call replaces the callback. Closing the spool drops it. */
typedef void (*bst_spool_flush_cb)(void *ud, int err);
int bst_spool_flush(bst_spool *sp, bst_spool_flush_cb cb, void *ud);

/* Reads up to max bytes from off. Returns 1 with *out set (a new buffer the caller owns, read from
 * memory) when the bytes are at hand, 0 when the read went to the aio pool (cb then runs on the
 * loop thread with the buffer, or NULL and a negative errno), or a negative errno. One read at a
 * time per spool. off at or past the end is -EINVAL. */
typedef void (*bst_spool_read_cb)(void *ud, bst_buf *b, int err);
int bst_spool_read(bst_spool *sp, uint64_t off, size_t max, bst_buf **out, bst_spool_read_cb cb,
		   void *ud);

/* Frees it and closes its file. A read or write still on the aio pool completes silently, and
 * no callback runs. NULL is ignored. */
void bst_spool_close(bst_spool *sp);

#endif

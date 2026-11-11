/* Body chain: ordered memory or file segments, consumed from the front.
 * Not thread-safe. Segments come from a slab made by bst_chain_slab_new, which may
 * be shared by chains of one worker. */
#ifndef BST_CHAIN_H
#define BST_CHAIN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "core/buf.h"
#include "core/slab.h"

/* Called once when a file segment is fully consumed or cleared. */
typedef void (*bst_chain_release_fn)(void *arg);

struct bst_seg;
typedef struct bst_chain {
	bst_slab *slab;
	struct bst_seg *head, *tail;
	uint64_t len;
} bst_chain;

bst_slab *bst_chain_slab_new(size_t per_chunk);
void bst_chain_init(bst_chain *c, bst_slab *slab);

/* Take their own buffer reference; the caller keeps its own. 0 on success, -1 on
 * exhaustion, if [off, off+len) is outside buf->len, or if the chain length would
 * exceed INT64_MAX (chain unchanged on -1). len 0 is a no-op success. */
int bst_chain_add_mem(bst_chain *c, bst_buf *b, size_t off, size_t len);
/* The fd is not owned. release (optional) runs on success paths only: when the
 * segment is consumed or cleared. On -1 it is not called and the caller keeps
 * ownership. len 0 is a no-op success; negative off/len or overflow is -1. */
int bst_chain_add_file(bst_chain *c, int fd, off_t off, off_t len);
int bst_chain_add_file_rel(bst_chain *c, int fd, off_t off, off_t len,
			   bst_chain_release_fn release, void *arg);

uint64_t bst_chain_len(const bst_chain *c);
/* Drops n bytes from the front (clamped to the chain length). */
void bst_chain_consume(bst_chain *c, uint64_t n);
/* Fills iov with leading memory segments, stopping at the first file segment.
 * Returns the number of entries. */
int bst_chain_to_iov(const bst_chain *c, struct iovec *iov, int max);
/* The buffers behind the same leading memory segments, one per iovec of bst_chain_to_iov
 * (no reference taken). For a sender that must keep them alive past the chain. */
int bst_chain_front_bufs(const bst_chain *c, bst_buf **bufs, int max);
/* Front segment is a file: returns 1 and fills fd/off/len; else 0. */
int bst_chain_front_file(const bst_chain *c, int *fd, off_t *off, off_t *len);
void bst_chain_clear(bst_chain *c);
/* Moves the first n bytes (clamped to the length of src) from src to dst, splitting the segment
 * the cut falls in: both parts keep the same buffer or file, and a file segment's release hook
 * runs with its last part. Same slab for both. 0, or -1 with both chains unchanged (exhaustion,
 * or dst's length would exceed INT64_MAX). */
int bst_chain_take(bst_chain *dst, bst_chain *src, uint64_t n);
/* Appends every segment of src to dst and leaves src empty, without copying or touching
 * references. Both chains must use the same slab. -1 (nothing moved) if dst's length would
 * exceed INT64_MAX. */
int bst_chain_move(bst_chain *dst, bst_chain *src);

#endif

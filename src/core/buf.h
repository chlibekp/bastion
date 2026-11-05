/* Refcounted byte buffer. Not thread-safe: a buffer belongs to one worker.
 *
 * A buffer either owns its memory (bst_buf_new: header and data in one malloc) or only
 * describes memory somebody else owns, such as a slot of a provided-buffer ring. For
 * the second kind the owner supplies a release hook that runs when the last reference
 * goes away. */
#ifndef BST_BUF_H
#define BST_BUF_H

#include <stddef.h>

typedef struct bst_buf bst_buf;

/* Called once when the last reference is dropped; b->data is still valid. For a header
 * made by bst_buf_init the hook may hand the header back to a pool and later re-init it
 * (or bst_buf_ref it, refs 0 -> 1). It must not touch a header made by bst_buf_wrap
 * after returning: that header is freed right after the hook. */
typedef void (*bst_buf_release_fn)(bst_buf *b, void *ctx);

struct bst_buf {
	unsigned char *data;
	size_t len;  /* bytes in use, set by the owner */
	size_t cap;
	size_t refs;
	bst_buf_release_fn release; /* may be NULL */
	void *ctx;
	unsigned char kind_; /* private: who frees the header */
};

/* NULL on exhaustion or size overflow. Starts with one reference, len 0. */
bst_buf *bst_buf_new(size_t cap);

/* Describe caller-owned memory with a malloc'd header. One reference, len 0. The hook
 * (may be NULL) runs at the last unref, then the header is freed. NULL on exhaustion. */
bst_buf *bst_buf_wrap(void *data, size_t cap, bst_buf_release_fn release, void *ctx);

/* Initialise a caller-owned header (for a pool). One reference, len 0. The header is
 * never freed by unref; only the hook runs. */
void bst_buf_init(bst_buf *b, void *data, size_t cap, bst_buf_release_fn release, void *ctx);

bst_buf *bst_buf_ref(bst_buf *b);
/* At zero: runs the release hook, or frees a bst_buf_new buffer. NULL is ignored. */
void bst_buf_unref(bst_buf *b);

#endif

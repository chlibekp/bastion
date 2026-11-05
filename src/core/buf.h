/* Refcounted byte buffer. Not thread-safe: a buffer belongs to one worker. */
#ifndef BST_BUF_H
#define BST_BUF_H

#include <stddef.h>

typedef struct bst_buf {
	unsigned char *data;
	size_t len;  /* bytes in use, set by the owner */
	size_t cap;
	size_t refs;
} bst_buf;

/* NULL on exhaustion or size overflow. Starts with one reference, len 0. */
bst_buf *bst_buf_new(size_t cap);
bst_buf *bst_buf_ref(bst_buf *b);
/* Frees at zero. NULL is ignored. */
void bst_buf_unref(bst_buf *b);

#endif

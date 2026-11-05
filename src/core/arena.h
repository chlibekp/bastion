/* Bump-pointer arena. Allocations are 16-byte aligned and live until reset or free.
 * Requests larger than the chunk size get their own allocation, released on reset. */
#ifndef BST_ARENA_H
#define BST_ARENA_H

#include <stddef.h>

typedef struct bst_arena bst_arena;

bst_arena *bst_arena_new(size_t chunk);
/* NULL on exhaustion or when size arithmetic would overflow. Never zeroed. */
void *bst_arena_alloc(bst_arena *a, size_t n);
/* Invalidates all allocations; keeps regular chunks for reuse, frees oversized ones. */
void bst_arena_reset(bst_arena *a);
void bst_arena_free(bst_arena *a);
/* Bytes obtained from malloc for chunks, including headers. */
size_t bst_arena_mapped(const bst_arena *a);

/* Total chunk-list steps taken by allocation so far; linear in chunk count by design. */
size_t bst_arena_walks(const bst_arena *a);

#endif

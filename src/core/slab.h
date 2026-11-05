/* Fixed-size object slab with a LIFO free list. Memory is held until bst_slab_free. */
#ifndef BST_SLAB_H
#define BST_SLAB_H

#include <stddef.h>

typedef struct bst_slab bst_slab;

bst_slab *bst_slab_new(size_t obj, size_t per_chunk);
/* NULL on exhaustion. Contents are unspecified. */
void *bst_slab_get(bst_slab *s);
void bst_slab_put(bst_slab *s, void *p);
void bst_slab_free(bst_slab *s);

#endif

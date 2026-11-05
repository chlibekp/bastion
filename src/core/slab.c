#include "core/slab.h"

#include <stdint.h>
#include <stdlib.h>

#include "core/poison.h"

#define ALIGN 16u

struct node {
	struct node *next;
};

struct schunk {
	struct schunk *next;
};

struct bst_slab {
	size_t stride;
	size_t per_chunk;
	struct node *free;
	struct schunk *chunks;
};

#define SHDR ((size_t)ALIGN)

bst_slab *bst_slab_new(size_t obj, size_t per_chunk)
{
	if (obj == 0 || per_chunk == 0 || obj > SIZE_MAX - ALIGN)
		return NULL;
	size_t stride = (obj + ALIGN - 1) & ~(size_t)(ALIGN - 1);
	if (stride < sizeof(struct node))
		stride = ALIGN;
	if (per_chunk > (SIZE_MAX - SHDR) / stride)
		return NULL;
	bst_slab *s = calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;
	s->stride = stride;
	s->per_chunk = per_chunk;
	return s;
}

static int grow(bst_slab *s)
{
	struct schunk *c = malloc(SHDR + s->stride * s->per_chunk);
	if (c == NULL)
		return -1;
	c->next = s->chunks;
	s->chunks = c;
	unsigned char *base = (unsigned char *)c + SHDR;
	for (size_t i = s->per_chunk; i-- > 0;) {
		struct node *n = (struct node *)(base + i * s->stride);
		n->next = s->free;
		s->free = n;
		BST_POISON(n, s->stride);
	}
	return 0;
}

void *bst_slab_get(bst_slab *s)
{
	if (s->free == NULL && grow(s) != 0)
		return NULL;
	BST_UNPOISON(s->free, s->stride);
	struct node *n = s->free;
	s->free = n->next;
	return n;
}

void bst_slab_put(bst_slab *s, void *p)
{
	if (p == NULL)
		return;
	struct node *n = p;
	n->next = s->free;
	s->free = n;
	BST_POISON(n, s->stride);
}

void bst_slab_free(bst_slab *s)
{
	if (s == NULL)
		return;
	while (s->chunks != NULL) {
		struct schunk *c = s->chunks;
		s->chunks = c->next;
		unsigned char *base = (unsigned char *)c + SHDR;
		BST_UNPOISON(base, s->stride * s->per_chunk);
		free(c);
	}
	free(s);
}

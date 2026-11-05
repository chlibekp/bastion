#include "core/arena.h"

#include <stdint.h>
#include <stdlib.h>

#include "core/poison.h"

#define ALIGN 16u
#define HDR ((sizeof(struct chunk) + ALIGN - 1) & ~(size_t)(ALIGN - 1))

struct chunk {
	struct chunk *next;
	size_t cap;  /* usable bytes after the header */
	size_t used;
} __attribute__((aligned(16)));

struct bst_arena {
	size_t chunk;         /* usable bytes per regular chunk */
	struct chunk *head;   /* regular chunks; current is the first with room */
	struct chunk *cur;
	struct chunk *large;  /* oversized, dedicated chunks */
	size_t mapped;
};

static unsigned char *data(struct chunk *c)
{
	return (unsigned char *)c + HDR;
}

static struct chunk *chunk_new(size_t cap)
{
	if (cap > SIZE_MAX - HDR)
		return NULL;
	struct chunk *c = malloc(HDR + cap);
	if (c == NULL)
		return NULL;
	c->next = NULL;
	c->cap = cap;
	c->used = 0;
	BST_POISON(data(c), cap);
	return c;
}

bst_arena *bst_arena_new(size_t chunk)
{
	if (chunk == 0 || chunk > SIZE_MAX - HDR - ALIGN)
		return NULL;
	bst_arena *a = calloc(1, sizeof(*a));
	if (a == NULL)
		return NULL;
	a->chunk = (chunk + ALIGN - 1) & ~(size_t)(ALIGN - 1);
	return a;
}

void *bst_arena_alloc(bst_arena *a, size_t n)
{
	if (n > SIZE_MAX - ALIGN)
		return NULL;
	size_t sz = (n + ALIGN - 1) & ~(size_t)(ALIGN - 1);
	if (sz == 0)
		sz = ALIGN;

	if (sz > a->chunk) {
		struct chunk *c = chunk_new(sz);
		if (c == NULL)
			return NULL;
		c->used = sz;
		c->next = a->large;
		a->large = c;
		a->mapped += HDR + sz;
		BST_UNPOISON(data(c), sz);
		return data(c);
	}

	while (a->cur != NULL && a->cur->cap - a->cur->used < sz)
		a->cur = a->cur->next;
	if (a->cur == NULL) {
		struct chunk *c = chunk_new(a->chunk);
		if (c == NULL)
			return NULL;
		struct chunk **tail = &a->head;
		while (*tail != NULL)
			tail = &(*tail)->next;
		*tail = c;
		a->cur = c;
		a->mapped += HDR + a->chunk;
	}
	void *p = data(a->cur) + a->cur->used;
	a->cur->used += sz;
	BST_UNPOISON(p, sz);
	return p;
}

void bst_arena_reset(bst_arena *a)
{
	while (a->large != NULL) {
		struct chunk *c = a->large;
		a->large = c->next;
		a->mapped -= HDR + c->cap;
		BST_UNPOISON(data(c), c->cap);
		free(c);
	}
	for (struct chunk *c = a->head; c != NULL; c = c->next) {
		c->used = 0;
		BST_POISON(data(c), c->cap);
	}
	a->cur = a->head;
}

void bst_arena_free(bst_arena *a)
{
	if (a == NULL)
		return;
	struct chunk *lists[2] = {a->head, a->large};
	for (int i = 0; i < 2; i++) {
		while (lists[i] != NULL) {
			struct chunk *c = lists[i];
			lists[i] = c->next;
			BST_UNPOISON(data(c), c->cap);
			free(c);
		}
	}
	free(a);
}

size_t bst_arena_mapped(const bst_arena *a)
{
	return a->mapped;
}

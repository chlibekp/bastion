#include "core/ring.h"

#include <stdlib.h>
#include <string.h>

#define PREFIX 4u

struct bst_spsc {
	struct bst_spsc_shm *shm;
	uint8_t *data;
	uint64_t cap;  /* trusted, process-local */
	uint64_t mask;
	/* Producer side. */
	uint64_t wr;        /* own write index */
	uint64_t cached_rd; /* last rd seen from shared memory */
	uint64_t rd;        /* consumer side: own read index */
	uint64_t cached_wr;       /* last wr seen from shared memory */
	bool corrupt;
};

static bst_spsc *make_handle(void *mem, size_t cap)
{
	if (mem == NULL || cap < 8 || (cap & (cap - 1)) != 0 || cap > UINT32_MAX ||
	    ((uintptr_t)mem & 63u) != 0)
		return NULL;
	bst_spsc *r = calloc(1, sizeof *r);
	if (r == NULL)
		return NULL;
	r->shm = mem;
	r->data = (uint8_t *)mem + BST_SPSC_HDR;
	r->cap = cap;
	r->mask = cap - 1;
	return r;
}

bst_spsc *bst_spsc_init(void *mem, size_t cap)
{
	bst_spsc *r = make_handle(mem, cap);
	if (r == NULL)
		return NULL;
	atomic_store_explicit(&r->shm->wr, 0, memory_order_relaxed);
	atomic_store_explicit(&r->shm->rd, 0, memory_order_release);
	return r;
}

/* Reads only. The shared indices are hostile input: they seed local state here and are
 * validated on every push and pop, so nothing is trusted just because it was seeded. */
bst_spsc *bst_spsc_attach(void *mem, size_t cap)
{
	bst_spsc *r = make_handle(mem, cap);
	if (r == NULL)
		return NULL;
	r->rd = r->cached_rd = atomic_load_explicit(&r->shm->rd, memory_order_acquire);
	r->wr = r->cached_wr = atomic_load_explicit(&r->shm->wr, memory_order_acquire);
	return r;
}

void bst_spsc_resync(bst_spsc *r)
{
	r->cached_wr = atomic_load_explicit(&r->shm->wr, memory_order_acquire);
	r->rd = r->cached_wr;
	r->corrupt = false;
	atomic_store_explicit(&r->shm->rd, r->rd, memory_order_release);
}

void bst_spsc_free(bst_spsc *r)
{
	free(r);
}

static void ring_write(bst_spsc *r, uint64_t pos, const void *src, size_t n)
{
	size_t off = (size_t)(pos & r->mask);
	size_t first = r->cap - off < n ? (size_t)r->cap - off : n;
	memcpy(r->data + off, src, first);
	memcpy(r->data, (const uint8_t *)src + first, n - first);
}

static void ring_read(const bst_spsc *r, uint64_t pos, void *dst, size_t n)
{
	size_t off = (size_t)(pos & r->mask);
	size_t first = r->cap - off < n ? (size_t)r->cap - off : n;
	memcpy(dst, r->data + off, first);
	memcpy((uint8_t *)dst + first, r->data, n - first);
}

bool bst_spsc_push(bst_spsc *r, const void *msg, uint32_t len)
{
	uint64_t need = (uint64_t)len + PREFIX; /* cannot overflow: len is 32-bit */
	if (need > r->cap)
		return false;
	uint64_t used = r->wr - r->cached_rd;
	if (used > r->cap || r->cap - used < need) {
		r->cached_rd = atomic_load_explicit(&r->shm->rd, memory_order_acquire);
		used = r->wr - r->cached_rd;
		/* A peer that claims more than we ever wrote is lying: treat as full. */
		if (used > r->cap || r->cap - used < need)
			return false;
	}
	ring_write(r, r->wr, &len, PREFIX);
	ring_write(r, r->wr + PREFIX, msg, len);
	r->wr += need;
	atomic_store_explicit(&r->shm->wr, r->wr, memory_order_release);
	return true;
}

int32_t bst_spsc_pop(bst_spsc *r, void *out, uint32_t max)
{
	if (r->corrupt)
		return BST_SPSC_CORRUPT;
	uint64_t avail = r->cached_wr - r->rd;
	if (avail == 0 || avail > r->cap) {
		r->cached_wr = atomic_load_explicit(&r->shm->wr, memory_order_acquire);
		avail = r->cached_wr - r->rd;
		if (avail == 0)
			return BST_SPSC_EMPTY;
	}
	/* The writer can never be ahead by more than the capacity, nor leave a partial
	 * prefix behind. Anything else means the shared index was tampered with. */
	if (avail > r->cap || avail < PREFIX)
		goto bad;
	uint32_t len;
	ring_read(r, r->rd, &len, PREFIX);
	if (len > r->cap - PREFIX || (uint64_t)len + PREFIX > avail || len > INT32_MAX)
		goto bad;
	if (len > max)
		return BST_SPSC_SMALL;
	ring_read(r, r->rd + PREFIX, out, len);
	r->rd += (uint64_t)len + PREFIX;
	atomic_store_explicit(&r->shm->rd, r->rd, memory_order_release);
	return (int32_t)len;
bad:
	r->corrupt = true;
	return BST_SPSC_CORRUPT;
}

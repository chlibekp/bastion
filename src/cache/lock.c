/* See lock.h. A word: tag (23 bits) << 41 | pass << 40 | deadline (40 bits of ms, relative to the
 * table's base, so about 34 years). 0 is a free slot. */
#include "cache/lock.h"

#include <stdatomic.h>

#define PROBE 4u
#define DL_BITS 40
#define DL_MASK ((1ull << DL_BITS) - 1)
#define PASS_BIT (1ull << DL_BITS)

struct bst_cachelock_table {
	uint64_t nslots;
	_Alignas(64) _Atomic uint64_t w[];
};

size_t bst_cachelock_size(size_t nslots)
{
	return sizeof(bst_cachelock_table) + nslots * sizeof(_Atomic uint64_t);
}

bst_cachelock_table *bst_cachelock_init(void *mem, size_t nslots)
{
	bst_cachelock_table *t = mem;
	t->nslots = nslots;
	return t;
}

static uint64_t tag_of(const bst_key *k)
{
	uint64_t h;
	__builtin_memcpy(&h, k->b + 8, sizeof h); /* other bytes than the slot's hash */
	return (h & 0x7fffffull) | 1; /* never 0: a word with tag 0 would read as free */
}

static uint64_t word(uint64_t tag, bool pass, uint64_t deadline)
{
	return tag << (DL_BITS + 1) | (pass ? PASS_BIT : 0) | (deadline & DL_MASK);
}

static uint64_t w_tag(uint64_t w)
{
	return w >> (DL_BITS + 1);
}

static uint64_t w_dl(uint64_t w)
{
	return w & DL_MASK;
}

bst_lock_rc bst_cachelock_try(bst_cachelock_table *t, const bst_key *k, unsigned *slot,
			      uint64_t deadline, uint64_t now_ms)
{
	size_t n = (size_t)t->nslots;
	if (n == 0)
		return BST_LOCK_FULL;
	uint64_t tag = tag_of(k), h = bst_key_u64(k);
	now_ms &= DL_MASK;
	uint64_t mine = word(tag, false, deadline);
	for (int round = 0; round < 2; round++) {
		/* round 0: this key's own slot; round 1: a free or expired one */
		for (unsigned i = 0; i < PROBE; i++) {
			unsigned at = (unsigned)((h + i) % n);
			uint64_t w = atomic_load_explicit(&t->w[at], memory_order_acquire);
			bool live = w != 0 && w_dl(w) > now_ms;
			if (round == 0) {
				if (w == 0 || w_tag(w) != tag)
					continue;
				if (live)
					return (w & PASS_BIT) ? BST_LOCK_PASS : BST_LOCK_HELD;
			} else if (live) {
				continue;
			}
			if (atomic_compare_exchange_strong_explicit(&t->w[at], &w, mine,
								    memory_order_acq_rel,
								    memory_order_acquire)) {
				*slot = at;
				return BST_LOCK_WON;
			}
			/* lost a race: whoever won may hold our key now */
			if (w != 0 && w_tag(w) == tag && w_dl(w) > now_ms)
				return (w & PASS_BIT) ? BST_LOCK_PASS : BST_LOCK_HELD;
		}
	}
	return BST_LOCK_FULL;
}

void bst_cachelock_release(bst_cachelock_table *t, const bst_key *k, unsigned slot,
			   uint64_t taken_deadline, bool pass, uint64_t pass_until)
{
	if (slot >= t->nslots)
		return;
	uint64_t mine = word(tag_of(k), false, taken_deadline);
	uint64_t next = pass ? word(tag_of(k), true, pass_until) : 0;
	(void)atomic_compare_exchange_strong_explicit(&t->w[slot], &mine, next, memory_order_acq_rel,
						      memory_order_relaxed);
}

bool bst_cachelock_expired(bst_cachelock_table *t, unsigned slot, uint64_t now_ms)
{
	if (slot >= t->nslots)
		return true;
	uint64_t w = atomic_load_explicit(&t->w[slot], memory_order_acquire);
	return w == 0 || w_dl(w) <= (now_ms & DL_MASK);
}

/* See index.h. */
#include "cache/index.h"

#include <string.h>

enum { S_EMPTY = 0, S_BUSY = 1, S_LIVE = 2, S_TOMB = 3 };
#define ST(w) ((w) & 3u)
#define GEN(w) ((w) >> 2)
#define WORD(g, s) (((g) << 2) | (s))
#define MAX_PROBE 64u
#define MAGIC 0x62737463696478ull /* "bstcidx" */

typedef struct slot {
	_Alignas(64) atomic_uint state;
	atomic_uint last_access;
	atomic_uint uses;
	atomic_ullong key[4];
	atomic_ullong size;
	atomic_llong stored_at_ms, req_time, resp_time;
} slot;

struct bst_cindex {
	uint64_t magic;
	uint64_t nslots;
	_Alignas(64) atomic_ullong bytes;
	atomic_ullong count;
	atomic_ullong full;
	atomic_uint scanned;
	_Alignas(64) slot s[];
};

size_t bst_cindex_size(size_t nslots)
{
	return sizeof(bst_cindex) + nslots * sizeof(slot);
}

bst_cindex *bst_cindex_init(void *mem, size_t nslots)
{
	bst_cindex *x = mem;
	x->magic = MAGIC;
	x->nslots = nslots;
	return x;
}

static void key_words(const bst_key *k, uint64_t w[4])
{
	memcpy(w, k->b, 32);
}

static bool key_is(slot *s, const uint64_t w[4])
{
	for (int i = 0; i < 4; i++)
		if (atomic_load_explicit(&s->key[i], memory_order_relaxed) != w[i])
			return false;
	return true;
}

static void read_slot(slot *s, bst_centry *e)
{
	uint64_t w[4];
	for (int i = 0; i < 4; i++)
		w[i] = atomic_load_explicit(&s->key[i], memory_order_relaxed);
	memcpy(e->key.b, w, 32);
	e->size = atomic_load_explicit(&s->size, memory_order_relaxed);
	e->stored_at_ms = atomic_load_explicit(&s->stored_at_ms, memory_order_relaxed);
	e->req_time = atomic_load_explicit(&s->req_time, memory_order_relaxed);
	e->resp_time = atomic_load_explicit(&s->resp_time, memory_order_relaxed);
	e->last_access = atomic_load_explicit(&s->last_access, memory_order_relaxed);
	e->uses = atomic_load_explicit(&s->uses, memory_order_relaxed);
}

/* The live slot of key, with its state word, or NULL. */
static slot *find(bst_cindex *x, const uint64_t w[4], unsigned *word)
{
	size_t n = x->nslots, h = (size_t)(w[0] % n);
	for (unsigned i = 0; i < MAX_PROBE && i < n; i++) {
		slot *s = &x->s[(h + i) % n];
		unsigned st = atomic_load_explicit(&s->state, memory_order_acquire);
		if (ST(st) == S_EMPTY)
			return NULL; /* never used: the probe chain ends */
		if (ST(st) == S_LIVE && key_is(s, w)) {
			*word = st;
			return s;
		}
	}
	return NULL;
}

bool bst_cindex_lookup(bst_cindex *x, const bst_key *k, bst_centry *out)
{
	uint64_t w[4];
	key_words(k, w);
	for (int tries = 0; tries < 4; tries++) {
		unsigned st;
		slot *s = find(x, w, &st);
		if (s == NULL)
			return false;
		read_slot(s, out);
		atomic_thread_fence(memory_order_acquire);
		if (atomic_load_explicit(&s->state, memory_order_relaxed) == st &&
		    memcmp(out->key.b, k->b, 32) == 0)
			return true;
	}
	return false;
}

static void write_fields(slot *s, const bst_centry *e)
{
	atomic_store_explicit(&s->size, e->size, memory_order_relaxed);
	atomic_store_explicit(&s->stored_at_ms, e->stored_at_ms, memory_order_relaxed);
	atomic_store_explicit(&s->req_time, e->req_time, memory_order_relaxed);
	atomic_store_explicit(&s->resp_time, e->resp_time, memory_order_relaxed);
	atomic_store_explicit(&s->last_access, e->last_access, memory_order_relaxed);
	atomic_store_explicit(&s->uses, e->uses > 0 ? e->uses : 1, memory_order_relaxed);
}

bool bst_cindex_insert(bst_cindex *x, const bst_centry *e)
{
	uint64_t w[4];
	key_words(&e->key, w);
	unsigned st;
	slot *old = find(x, w, &st);
	if (old != NULL) {
		/* the same key filled again: take the slot over (BUSY), so readers see no mix */
		if (atomic_compare_exchange_strong_explicit(&old->state, &st, WORD(GEN(st) + 1, S_BUSY),
							    memory_order_acq_rel, memory_order_relaxed)) {
			uint64_t was = atomic_load_explicit(&old->size, memory_order_relaxed);
			write_fields(old, e);
			atomic_fetch_sub_explicit(&x->bytes, was, memory_order_relaxed);
			atomic_fetch_add_explicit(&x->bytes, e->size, memory_order_relaxed);
			atomic_store_explicit(&old->state, WORD(GEN(st) + 1, S_LIVE), memory_order_release);
			return true;
		}
	}
	size_t n = x->nslots, h = (size_t)(w[0] % n);
	for (unsigned i = 0; i < MAX_PROBE && i < n; i++) {
		slot *s = &x->s[(h + i) % n];
		unsigned cur = atomic_load_explicit(&s->state, memory_order_acquire);
		if (ST(cur) != S_EMPTY && ST(cur) != S_TOMB)
			continue;
		if (!atomic_compare_exchange_strong_explicit(&s->state, &cur, WORD(GEN(cur) + 1, S_BUSY),
							     memory_order_acq_rel, memory_order_relaxed))
			continue;
		for (int j = 0; j < 4; j++)
			atomic_store_explicit(&s->key[j], w[j], memory_order_relaxed);
		write_fields(s, e);
		atomic_fetch_add_explicit(&x->bytes, e->size, memory_order_relaxed);
		atomic_fetch_add_explicit(&x->count, 1, memory_order_relaxed);
		atomic_store_explicit(&s->state, WORD(GEN(cur) + 1, S_LIVE), memory_order_release);
		return true;
	}
	atomic_fetch_add_explicit(&x->full, 1, memory_order_relaxed);
	return false;
}

uint32_t bst_cindex_touch(bst_cindex *x, const bst_key *k, uint32_t now)
{
	uint64_t w[4];
	key_words(k, w);
	unsigned st;
	slot *s = find(x, w, &st);
	if (s == NULL)
		return 0;
	uint32_t last = atomic_load_explicit(&s->last_access, memory_order_relaxed);
	if (now != last && now - last >= 1)
		atomic_store_explicit(&s->last_access, now, memory_order_relaxed);
	return atomic_fetch_add_explicit(&s->uses, 1, memory_order_relaxed) + 1;
}

bool bst_cindex_refresh(bst_cindex *x, const bst_key *k, int64_t req_time, int64_t resp_time)
{
	uint64_t w[4];
	key_words(k, w);
	unsigned st;
	slot *s = find(x, w, &st);
	if (s == NULL)
		return false;
	atomic_store_explicit(&s->req_time, req_time, memory_order_relaxed);
	atomic_store_explicit(&s->resp_time, resp_time, memory_order_relaxed);
	return true;
}

static bool kill_slot(bst_cindex *x, slot *s, unsigned st)
{
	uint64_t size = atomic_load_explicit(&s->size, memory_order_relaxed);
	if (!atomic_compare_exchange_strong_explicit(&s->state, &st, WORD(GEN(st) + 1, S_TOMB),
						     memory_order_acq_rel, memory_order_relaxed))
		return false;
	atomic_fetch_sub_explicit(&x->bytes, size, memory_order_relaxed);
	atomic_fetch_sub_explicit(&x->count, 1, memory_order_relaxed);
	return true;
}

bool bst_cindex_remove(bst_cindex *x, const bst_key *k)
{
	uint64_t w[4];
	key_words(k, w);
	bool any = false;
	unsigned st;
	slot *s;
	while ((s = find(x, w, &st)) != NULL) { /* a racing double insert leaves two: both go */
		if (kill_slot(x, s, st))
			any = true;
	}
	return any;
}

bool bst_cindex_slot(bst_cindex *x, size_t i, bst_centry *out)
{
	if (i >= x->nslots)
		return false;
	slot *s = &x->s[i];
	unsigned st = atomic_load_explicit(&s->state, memory_order_acquire);
	if (ST(st) != S_LIVE)
		return false;
	read_slot(s, out);
	atomic_thread_fence(memory_order_acquire);
	return atomic_load_explicit(&s->state, memory_order_relaxed) == st;
}

uint64_t bst_cindex_bytes(const bst_cindex *x)
{
	return atomic_load_explicit(&((bst_cindex *)x)->bytes, memory_order_relaxed);
}

uint64_t bst_cindex_count(const bst_cindex *x)
{
	return atomic_load_explicit(&((bst_cindex *)x)->count, memory_order_relaxed);
}

uint64_t bst_cindex_full_count(const bst_cindex *x)
{
	return atomic_load_explicit(&((bst_cindex *)x)->full, memory_order_relaxed);
}

size_t bst_cindex_nslots(const bst_cindex *x)
{
	return (size_t)x->nslots;
}

bool bst_cindex_scanned(const bst_cindex *x)
{
	return atomic_load_explicit(&((bst_cindex *)x)->scanned, memory_order_acquire) != 0;
}

void bst_cindex_set_scanned(bst_cindex *x)
{
	atomic_store_explicit(&x->scanned, 1, memory_order_release);
}

/* See escalate.h. */
#include "sec/escalate.h"

#include "core/hash.h"

#include <stdatomic.h>
#include <string.h>
#include <sys/random.h>

/* A strike slot: the key (0: free) and the state, window start in ms << 20 | count. */
typedef struct strike {
	_Atomic uint64_t key;
	_Atomic uint64_t st;
} strike;

#define CNT_BITS 20
#define CNT_MAX ((1ull << CNT_BITS) - 1)
#define PROBE 4

typedef struct ring {
	_Atomic uint64_t head; /* master's */
	char pad1[56];
	_Atomic uint64_t tail; /* the worker's */
	char pad2[56];
	bst_block_req e[BST_ESC_RING];
} ring;

typedef struct esc_hdr {
	uint8_t sipkey[16];
	uint64_t nworkers;
	char pad[40];
} esc_hdr;

static esc_hdr *g_hdr;
static strike *g_strikes;
static ring *g_rings;
static int g_slot = -1;
static _Atomic uint64_t g_dropped;

size_t bst_escalate_bytes(int nworkers)
{
	return sizeof(esc_hdr) + BST_ESC_STRIKE_SLOTS * sizeof(strike) + (size_t)(nworkers > 0 ? nworkers : 1) * sizeof(ring);
}

int bst_escalate_attach(void *mem, int nworkers)
{
	g_hdr = mem;
	g_strikes = (strike *)(g_hdr + 1);
	g_rings = (ring *)(g_strikes + BST_ESC_STRIKE_SLOTS);
	g_hdr->nworkers = (uint64_t)(nworkers > 0 ? nworkers : 1);
	g_slot = -1;
	if (getrandom(g_hdr->sipkey, sizeof g_hdr->sipkey, 0) != (ssize_t)sizeof g_hdr->sipkey)
		return -1;
	return 0;
}

void bst_escalate_worker(int slot)
{
	g_slot = g_hdr != NULL && slot >= 0 && (uint64_t)slot < g_hdr->nworkers ? slot : -1;
}

static void masked(const bst_ip *ip, unsigned v6p, bst_ip *out, unsigned *prefix)
{
	*out = bst_ip_canon(ip);
	unsigned p = out->family == BST_IP_V4 ? 32 : v6p >= 48 && v6p <= 128 ? v6p : 64;
	unsigned n = out->family == BST_IP_V4 ? 4 : 16;
	for (unsigned i = 0; i < 16; i++) {
		unsigned bits = i < n && p > i * 8 ? p - i * 8 : 0;
		out->b[i] &= bits >= 8 ? 0xff : (uint8_t)(0xff00u >> bits);
	}
	*prefix = p;
}

/* The slot of key: its own, a free one, or (none of the probed) the one whose window began
 * longest ago, taken over. */
static strike *find(uint64_t key)
{
	uint32_t mask = BST_ESC_STRIKE_SLOTS - 1, i0 = (uint32_t)(key >> 32) & mask;
	strike *oldest = NULL;
	uint64_t oldest_st = UINT64_MAX;
	for (unsigned i = 0; i < PROBE; i++) {
		strike *s = &g_strikes[(i0 + i) & mask];
		uint64_t k = atomic_load_explicit(&s->key, memory_order_acquire);
		if (k == key)
			return s;
		if (k == 0) {
			if (atomic_compare_exchange_strong_explicit(&s->key, &k, key, memory_order_acq_rel,
								    memory_order_acquire) || k == key)
				return s;
		}
		uint64_t st = atomic_load_explicit(&s->st, memory_order_relaxed);
		if (st < oldest_st) {
			oldest_st = st;
			oldest = s;
		}
	}
	uint64_t k = atomic_load_explicit(&oldest->key, memory_order_acquire);
	if (atomic_compare_exchange_strong_explicit(&oldest->key, &k, key, memory_order_acq_rel, memory_order_acquire))
		atomic_store_explicit(&oldest->st, 0, memory_order_relaxed);
	return oldest; /* a lost race: counted with whoever won, never more than one request */
}

static bool ring_put(const bst_block_req *r)
{
	ring *q = &g_rings[g_slot];
	uint64_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
	uint64_t head = atomic_load_explicit(&q->head, memory_order_acquire);
	if (tail - head >= BST_ESC_RING) {
		atomic_fetch_add_explicit(&g_dropped, 1, memory_order_relaxed);
		return false;
	}
	q->e[tail % BST_ESC_RING] = *r;
	atomic_store_explicit(&q->tail, tail + 1, memory_order_release);
	return true;
}

bst_strike_rc bst_escalate_strike(const bst_escalate_cfg *cfg, const bst_ip *ip, bst_strike_kind kind,
				  const bst_strike_src *src, unsigned ipv6_prefix, uint64_t now_us)
{
	if (cfg == NULL || cfg->after == 0 || g_hdr == NULL || g_slot < 0 || ip == NULL || kind >= BST_STRIKE_KINDS)
		return BST_STRIKE_OFF;
	if (src == NULL || !src->validated)
		return BST_STRIKE_IGNORED; /* spoofable: never ask to block it */
	bst_ip m;
	unsigned prefix;
	masked(ip, ipv6_prefix, &m, &prefix);
	struct {
		uint8_t fam, prefix, kind, pad;
		uint8_t b[16];
		uintptr_t rule;
	} kb;
	memset(&kb, 0, sizeof kb);
	kb.fam = m.family;
	kb.prefix = (uint8_t)prefix;
	kb.kind = (uint8_t)kind;
	memcpy(kb.b, m.b, 16);
	kb.rule = (uintptr_t)cfg; /* the same in every worker: forked after the config loaded */
	uint64_t key = bst_siphash13(g_hdr->sipkey, &kb, sizeof kb) | 1u;
	strike *s = find(key);
	uint64_t now_ms = now_us / 1000 + 1, window_ms = cfg->window_us / 1000, cnt;
	uint64_t old = atomic_load_explicit(&s->st, memory_order_relaxed), nw;
	do {
		uint64_t start = old >> CNT_BITS;
		cnt = old & CNT_MAX;
		if (old == 0 || now_ms < start || now_ms - start >= window_ms) {
			start = now_ms;
			cnt = 1;
		} else if (cnt < CNT_MAX) {
			cnt++;
		}
		nw = start << CNT_BITS | cnt;
	} while (!atomic_compare_exchange_weak_explicit(&s->st, &old, nw, memory_order_acq_rel, memory_order_relaxed));
	if (cnt != cfg->after)
		return BST_STRIKE_COUNTED;
	bst_block_req r;
	memset(&r, 0, sizeof r);
	r.family = m.family;
	r.prefix = (uint8_t)prefix;
	r.flags = src->l7_only ? BST_BLOCK_L7 : 0;
	r.kind = (uint8_t)kind;
	memcpy(r.addr, m.b, 16);
	r.ttl_us = cfg->block_us;
	return ring_put(&r) ? BST_STRIKE_SENT : BST_STRIKE_DROPPED;
}

size_t bst_escalate_drain(int slot, bst_block_req *out, size_t cap)
{
	if (g_hdr == NULL || slot < 0 || (uint64_t)slot >= g_hdr->nworkers)
		return 0;
	ring *q = &g_rings[slot];
	uint64_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
	uint64_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
	size_t n = 0;
	/* a tail more than a ring ahead is a worker's lie: take what the ring can hold */
	if (tail - head > BST_ESC_RING)
		head = tail - BST_ESC_RING;
	while (head != tail && n < cap)
		out[n++] = q->e[head++ % BST_ESC_RING];
	atomic_store_explicit(&q->head, head, memory_order_release);
	return n;
}

uint64_t bst_escalate_dropped(void)
{
	return atomic_load_explicit(&g_dropped, memory_order_relaxed);
}

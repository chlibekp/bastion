/* See attack.h. */
#include "sec/attack.h"

#include <stdatomic.h>

typedef struct row {
	_Atomic uint64_t req, ref;
	char pad[48]; /* a row per cache line: workers do not share lines */
} row;

typedef struct hdr {
	_Atomic uint32_t on;	 /* the helper's decision */
	_Atomic int32_t forced;	 /* +1 on, -1 off, 0 automatic (Phase 14) */
	uint64_t nworkers;
	char pad[48];
} hdr;

static hdr *g_hdr;
static row *g_rows;
static int g_slot = -1;

size_t bst_attack_bytes(int nworkers)
{
	return sizeof(hdr) + (size_t)(nworkers > 0 ? nworkers : 1) * sizeof(row);
}

void bst_attack_attach(void *mem, int nworkers)
{
	g_hdr = mem;
	g_rows = (row *)(g_hdr + 1);
	g_hdr->nworkers = (uint64_t)(nworkers > 0 ? nworkers : 1);
	g_slot = -1;
}

void bst_attack_worker(int slot)
{
	g_slot = g_hdr != NULL && slot >= 0 && (uint64_t)slot < g_hdr->nworkers ? slot : -1;
}

void bst_attack_request(void)
{
	if (g_slot >= 0)
		atomic_fetch_add_explicit(&g_rows[g_slot].req, 1, memory_order_relaxed);
}

void bst_attack_refusal(void)
{
	if (g_slot >= 0)
		atomic_fetch_add_explicit(&g_rows[g_slot].ref, 1, memory_order_relaxed);
}

bool bst_attack_on(void)
{
	if (g_hdr == NULL)
		return false;
	int32_t f = atomic_load_explicit(&g_hdr->forced, memory_order_relaxed);
	if (f != 0)
		return f > 0;
	return atomic_load_explicit(&g_hdr->on, memory_order_relaxed) != 0;
}

void bst_attack_force(int how)
{
	if (g_hdr != NULL)
		atomic_store_explicit(&g_hdr->forced, how > 0 ? 1 : how < 0 ? -1 : 0, memory_order_relaxed);
}

int bst_attack_sample(const bst_attack_cfg *c, bst_attack_state *st, uint64_t now_us)
{
	if (g_hdr == NULL)
		return 0;
	uint64_t req = 0, ref = 0;
	for (uint64_t i = 0; i < g_hdr->nworkers; i++) {
		req += atomic_load_explicit(&g_rows[i].req, memory_order_relaxed);
		ref += atomic_load_explicit(&g_rows[i].ref, memory_order_relaxed);
	}
	if (st->last_us == 0 || now_us <= st->last_us) {
		st->last_req = req;
		st->last_ref = ref;
		st->last_us = now_us;
		return 0;
	}
	uint64_t dt = now_us - st->last_us;
	/* per second, rounded to the nearest; a worker's replacement starts its row at 0 again */
	st->rps = req >= st->last_req ? ((req - st->last_req) * 1000000u + dt / 2) / dt : 0;
	st->refusals_ps = ref >= st->last_ref ? ((ref - st->last_ref) * 1000000u + dt / 2) / dt : 0;
	st->last_req = req;
	st->last_ref = ref;
	st->last_us = now_us;
	bool above = (c->rps > 0 && st->rps >= c->rps) || (c->block_rate > 0 && st->refusals_ps >= c->block_rate);
	bool on = atomic_load_explicit(&g_hdr->on, memory_order_relaxed) != 0;
	if (above) {
		st->below_since_us = 0;
		if (!on) {
			atomic_store_explicit(&g_hdr->on, 1, memory_order_relaxed);
			return 1;
		}
		return 0;
	}
	if (!on)
		return 0;
	if (st->below_since_us == 0)
		st->below_since_us = now_us;
	if (now_us - st->below_since_us >= c->hold_s * 1000000u) {
		atomic_store_explicit(&g_hdr->on, 0, memory_order_relaxed);
		st->below_since_us = 0;
		return -1;
	}
	return 0;
}

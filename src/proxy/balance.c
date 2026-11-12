/* See balance.h. */
#include "proxy/balance.h"

#include "core/hash.h"
#include "proxy/pool.h"
#include "route/vars.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#define RR_SCALE 100	     /* weights are scaled so a slow start can give a fraction of one */
#define RING_POINTS 160	     /* ring points per unit of weight */
#define LOAD_FACTOR 1.25     /* bounded load: at most this times the average */
#define EWMA_TAU_MS 10000.0  /* peak_ewma decay time */
#define HASH_PROBES 20

#ifdef BST_TEST
unsigned (*bst_test_balance_load)(const bst_peer *p);
#endif

static unsigned load_of(const bst_peer *p)
{
#ifdef BST_TEST
	if (bst_test_balance_load != NULL)
		return bst_test_balance_load(p);
#endif
	return bst_pool_active(p);
}

typedef struct ring_pt {
	uint64_t h;
	uint32_t peer;
} ring_pt;

typedef struct ustate {
	const bst_cfg_upstream *u;
	size_t n;
	int64_t *cur;	    /* smooth round robin */
	double *ewma;	    /* peak_ewma, milliseconds */
	uint64_t *ewma_t;
	uint64_t *up_since; /* slow start: when the peer came back, 0 = long ago */
	uint8_t *was_up;
	ring_pt *ring;
	size_t nring;
	size_t rr;
} ustate;

static ustate *g_st; /* per worker, by upstream index */
static size_t g_nst;
static uint64_t g_rand;

static const uint8_t hash_key[16] = { 'b', 'a', 's', 't', 'i', 'o', 'n', '-',
				      'b', 'a', 'l', 'a', 'n', 'c', 'e', '!' };

static uint64_t hash(const void *p, size_t n)
{
	return bst_siphash13(hash_key, p, n);
}

static uint64_t rnd(void)
{
	if (g_rand == 0 && (getrandom(&g_rand, sizeof g_rand, 0) != sizeof g_rand || g_rand == 0))
		g_rand = 0x9e3779b97f4a7c15ull;
	g_rand ^= g_rand << 13;
	g_rand ^= g_rand >> 7;
	g_rand ^= g_rand << 17;
	return g_rand;
}

static void st_free(ustate *s)
{
	free(s->cur);
	free(s->ewma);
	free(s->ewma_t);
	free(s->up_since);
	free(s->was_up);
	free(s->ring);
	memset(s, 0, sizeof *s);
}

#ifdef BST_TEST
void bst_balance_test_reset(void)
{
	for (size_t i = 0; i < g_nst; i++)
		st_free(&g_st[i]);
	free(g_st);
	g_st = NULL;
	g_nst = 0;
}
#endif

static int cmp_pt(const void *a, const void *b)
{
	const ring_pt *x = a, *y = b;
	return x->h < y->h ? -1 : x->h > y->h ? 1 : (x->peer < y->peer ? -1 : x->peer > y->peer);
}

static int build_ring(ustate *s, const bst_cfg_upstream *u)
{
	size_t total = 0;
	for (size_t i = 0; i < u->npeers; i++)
		total += (size_t)u->peers[i].weight * RING_POINTS;
	s->ring = malloc((total ? total : 1) * sizeof *s->ring);
	if (s->ring == NULL)
		return -1;
	for (size_t i = 0; i < u->npeers; i++) {
		const bst_peer *p = &u->peers[i];
		const bst_up_server *sv = &u->servers[p->server];
		for (unsigned j = 0; j < p->weight * RING_POINTS; j++) {
			/* the server's name and the peer's place in it: stable across address changes */
			char id[300];
			int n = snprintf(id, sizeof id, "%s:%u/%zu#%u", sv->host, sv->port,
					 i - sv->first_peer, j);
			s->ring[s->nring++] = (ring_pt){ hash(id, (size_t)n), (uint32_t)i };
		}
	}
	qsort(s->ring, s->nring, sizeof *s->ring, cmp_pt);
	return 0;
}

static ustate *state_of(const bst_cfg_upstream *u)
{
	if (u->index >= g_nst) {
		size_t n = u->index + 8;
		ustate *ns = realloc(g_st, n * sizeof *ns);
		if (ns == NULL)
			return NULL;
		memset(ns + g_nst, 0, (n - g_nst) * sizeof *ns);
		g_st = ns;
		g_nst = n;
	}
	ustate *s = &g_st[u->index];
	if (s->u == u && s->n == u->npeers)
		return s;
	st_free(s);
	size_t n = u->npeers ? u->npeers : 1;
	s->cur = calloc(n, sizeof *s->cur);
	s->ewma = calloc(n, sizeof *s->ewma);
	s->ewma_t = calloc(n, sizeof *s->ewma_t);
	s->up_since = calloc(n, sizeof *s->up_since);
	s->was_up = malloc(n);
	if (s->cur == NULL || s->ewma == NULL || s->ewma_t == NULL || s->up_since == NULL ||
	    s->was_up == NULL || (u->balance == BST_BAL_HASH && u->hash_consistent && build_ring(s, u))) {
		st_free(s);
		return NULL;
	}
	memset(s->was_up, 1, n);
	s->u = u;
	s->n = u->npeers;
	return s;
}

static uint64_t now_of(const bst_pick_ctx *ctx)
{
	if (ctx != NULL && ctx->now_ms != 0)
		return ctx->now_ms;
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Health with the slow-start bookkeeping: a peer seen down and then up again starts its ramp. */
static bool peer_up(ustate *s, size_t i, const bst_peer *p, uint64_t now)
{
	bool up = bst_peer_up(p);
	if (up && !s->was_up[i])
		s->up_since[i] = now;
	s->was_up[i] = up;
	return up;
}

/* Weight times RR_SCALE, reduced during slow start (never below 1). */
static int64_t eff_weight(const ustate *s, size_t i, const bst_peer *p, uint64_t now)
{
	int64_t w = (int64_t)p->weight * RR_SCALE;
	if (p->slow_start_ms != 0 && s->up_since[i] != 0 && now - s->up_since[i] < p->slow_start_ms) {
		w = (int64_t)((double)w * (double)(now - s->up_since[i]) / (double)p->slow_start_ms);
		if (w < 1)
			w = 1;
	}
	return w;
}

typedef struct cand {
	size_t idx[64];
	bst_sockaddr addr[64];
	size_t n;
} cand;

/* The usable peers of one tier (primaries or backups), at most 64 considered. */
static void usable(ustate *s, const bst_cfg_upstream *u, bool backup, uint64_t now, cand *c)
{
	c->n = 0;
	for (size_t i = 0; i < u->npeers && c->n < 64; i++) {
		const bst_peer *p = &u->peers[i];
		bool up = peer_up(s, i, p, now);
		if (p->backup != backup || !up)
			continue;
		if (p->max_conns != 0 && load_of(p) >= p->max_conns)
			continue;
		if (!bst_peer_addr(p, &c->addr[c->n]))
			continue;
		c->idx[c->n++] = i;
	}
}

static size_t pick_rr(ustate *s, const bst_cfg_upstream *u, const cand *c, uint64_t now)
{
	int64_t total = 0;
	size_t best = 0;
	for (size_t k = 0; k < c->n; k++) {
		size_t i = c->idx[k];
		int64_t w = eff_weight(s, i, &u->peers[i], now);
		s->cur[i] += w;
		total += w;
		if (s->cur[i] > s->cur[c->idx[best]])
			best = k;
	}
	s->cur[c->idx[best]] -= total;
	return best;
}

static size_t pick_least(ustate *s, const bst_cfg_upstream *u, const cand *c, uint64_t now)
{
	size_t best = SIZE_MAX;
	double bc = 0;
	size_t start = s->rr++;
	for (size_t j = 0; j < c->n; j++) {
		size_t k = (start + j) % c->n;
		size_t i = c->idx[k];
		double cost = ((double)load_of(&u->peers[i]) + 1.0) / (double)eff_weight(s, i, &u->peers[i], now);
		if (best == SIZE_MAX || cost < bc) {
			best = k;
			bc = cost;
		}
	}
	return best;
}

static double ewma_cost(const ustate *s, const bst_cfg_upstream *u, size_t i)
{
	return (s->ewma[i] + 1.0) * ((double)load_of(&u->peers[i]) + 1.0) / (double)u->peers[i].weight;
}

static size_t pick_ewma(ustate *s, const bst_cfg_upstream *u, const cand *c)
{
	if (c->n == 1)
		return 0;
	size_t a = (size_t)(rnd() % c->n), b = (size_t)(rnd() % (c->n - 1));
	if (b >= a)
		b++;
	return ewma_cost(s, u, c->idx[a]) <= ewma_cost(s, u, c->idx[b]) ? a : b;
}

static bst_str key_of(const bst_cfg_upstream *u, const bst_pick_ctx *ctx)
{
	if (ctx->s == NULL || u->hash_key == NULL)
		return ctx->key;
	bst_var_ctx vc;
	bst_var_ctx_init(&vc, ctx->s);
	bst_str k = bst_tpl_eval(u->hash_key, &vc, ctx->s->arena);
	return bst_str_failed(k) ? (bst_str){ "", 0 } : k;
}

static size_t pick_hash(ustate *s, const bst_cfg_upstream *u, const cand *c, bst_str key)
{
	uint64_t h = hash(key.p, key.len);
	if (!u->hash_consistent || s->nring == 0) {
		/* plain: modulo all peers, so the mapping does not depend on who is down; probe on */
		for (unsigned t = 0; t < HASH_PROBES; t++) {
			size_t i = (size_t)(h % u->npeers);
			for (size_t k = 0; k < c->n; k++)
				if (c->idx[k] == i)
					return k;
			h = hash(&h, sizeof h);
		}
		return pick_rr(s, u, c, 0);
	}
	/* consistent with bounded load */
	double total = 1;
	for (size_t k = 0; k < c->n; k++)
		total += load_of(&u->peers[c->idx[k]]);
	double lim = LOAD_FACTOR * total / (double)c->n;
	double cap = (double)(uint64_t)lim + ((double)(uint64_t)lim < lim ? 1.0 : 0.0); /* ceil, no libm */
	size_t lo = 0, hi = s->nring;
	while (lo < hi) {
		size_t mid = (lo + hi) / 2;
		if (s->ring[mid].h < h)
			lo = mid + 1;
		else
			hi = mid;
	}
	size_t fallback = SIZE_MAX;
	for (size_t step = 0; step < s->nring; step++) {
		uint32_t i = s->ring[(lo + step) % s->nring].peer;
		for (size_t k = 0; k < c->n; k++) {
			if (c->idx[k] != i)
				continue;
			if (fallback == SIZE_MAX)
				fallback = k;
			if ((double)load_of(&u->peers[i]) < cap)
				return k;
		}
	}
	return fallback == SIZE_MAX ? 0 : fallback;
}

const bst_peer *bst_balance_pick(const bst_cfg_upstream *u, const bst_pick_ctx *ctx,
				 bst_sockaddr *addr)
{
	if (u->npeers == 0)
		return NULL;
	ustate *s = state_of(u);
	if (s == NULL)
		return NULL;
	uint64_t now = now_of(ctx);
	cand c;
	usable(s, u, false, now, &c);
	if (c.n == 0)
		usable(s, u, true, now, &c);
	if (c.n == 0)
		return NULL;
	size_t k;
	switch (u->balance) {
	case BST_BAL_LEAST_CONN:
		k = pick_least(s, u, &c, now);
		break;
	case BST_BAL_HASH:
		k = pick_hash(s, u, &c, key_of(u, ctx));
		break;
	case BST_BAL_PEAK_EWMA:
		k = pick_ewma(s, u, &c);
		break;
	default:
		k = pick_rr(s, u, &c, now);
		break;
	}
	*addr = c.addr[k];
	return &u->peers[c.idx[k]];
}

void bst_balance_observe(const bst_cfg_upstream *u, const bst_peer *p, uint64_t latency_ms,
			 uint64_t now_ms)
{
	ustate *s = state_of(u);
	if (s == NULL)
		return;
	size_t i = (size_t)(p - u->peers);
	if (i >= s->n)
		return;
	double lat = (double)latency_ms;
	if (lat > s->ewma[i] || s->ewma_t[i] == 0) {
		s->ewma[i] = lat; /* a peak counts at once */
	} else {
		double dt = (double)(now_ms - s->ewma_t[i]);
		double x = dt / EWMA_TAU_MS; /* e^-x without libm: close enough for a decay */
		double w = 1.0 / (1.0 + x + x * x / 2.0 + x * x * x / 6.0);
		s->ewma[i] = s->ewma[i] * w + lat * (1.0 - w);
	}
	s->ewma_t[i] = now_ms ? now_ms : 1;
}

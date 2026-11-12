/* See balance.h. Round robin over the peers that have an address, primaries first. */
#include "proxy/balance.h"

#include "proxy/pool.h"

#include <stdlib.h>

static size_t *g_rr; /* per worker, by upstream index */
static size_t g_nrr;

static size_t *rr_of(const bst_cfg_upstream *u)
{
	if (u->index >= g_nrr) {
		size_t n = u->index + 8;
		size_t *nr = realloc(g_rr, n * sizeof *nr);
		if (nr == NULL)
			return NULL;
		for (size_t i = g_nrr; i < n; i++)
			nr[i] = 0;
		g_rr = nr;
		g_nrr = n;
	}
	return &g_rr[u->index];
}

static bool usable(const bst_peer *p, bst_sockaddr *addr)
{
	if (p->max_conns != 0 && bst_pool_active(p) >= p->max_conns)
		return false;
	return bst_peer_addr(p, addr);
}

const bst_peer *bst_balance_pick(const bst_cfg_upstream *u, const bst_pick_ctx *ctx,
				 bst_sockaddr *addr)
{
	(void)ctx;
	size_t *rr = rr_of(u);
	size_t start = rr != NULL ? *rr : 0;
	for (int backup = 0; backup < 2; backup++) {
		for (size_t k = 0; k < u->npeers; k++) {
			size_t i = (start + k) % u->npeers;
			const bst_peer *p = &u->peers[i];
			if (p->backup != (backup == 1) || !usable(p, addr))
				continue;
			if (rr != NULL)
				*rr = i + 1;
			return p;
		}
	}
	return NULL;
}

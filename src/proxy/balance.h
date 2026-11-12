/* Picking the peer for a request (`balance` in an upstream block). State is per worker: each
 * worker balances on its own and only health is shared (proxy/upstream.h). Peers without an
 * address now (a `resolve` server not yet resolved), peers marked down and peers at max_conns are
 * skipped; `backup` peers take requests only when no primary can.
 *
 *   round_robin  smooth weighted round robin (the interleaved sequence nginx uses)
 *   least_conn   fewest open requests relative to weight, ties in turn
 *   hash         the key's hash modulo the peers, or with `consistent` a ring of 160 points per
 *                weight unit with bounded load (a peer over 1.25 times the average load passes
 *                the key on along the ring)
 *   peak_ewma    power of two choices on latency EWMA times open requests
 * slow_start: a peer that comes back up gets a share that ramps from almost nothing to its full
 * weight over the window (round_robin and least_conn). */
#ifndef BST_PROXY_BALANCE_H
#define BST_PROXY_BALANCE_H

#include "http/stream.h"
#include "proxy/upstream.h"

typedef struct bst_pick_ctx {
	bst_stream *s;	 /* the request: `hash` keys are evaluated on it; NULL in tests */
	bst_str key;	 /* the key when s is NULL */
	uint64_t now_ms; /* 0: the monotonic clock */
} bst_pick_ctx;

/* The peer for this request with its current address in *addr, or NULL when none can take it. */
const bst_peer *bst_balance_pick(const bst_cfg_upstream *u, const bst_pick_ctx *ctx,
				 bst_sockaddr *addr);
/* A response head arrived latency_ms after the request went out (peak_ewma). */
void bst_balance_observe(const bst_cfg_upstream *u, const bst_peer *p, uint64_t latency_ms,
			 uint64_t now_ms);

#ifdef BST_TEST
/* Replaces the open-request count of a peer (least_conn, bounded load, peak_ewma). */
extern unsigned (*bst_test_balance_load)(const bst_peer *p);
/* Forgets every upstream's balancing state. */
void bst_balance_test_reset(void);
#endif

#endif

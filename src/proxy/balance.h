/* Picking the peer for a request. State is per worker (each worker balances on its own); only
 * health is shared. Peers without an address now (a `resolve` server not yet resolved) are
 * skipped, and `backup` peers take requests only when no primary can. */
#ifndef BST_PROXY_BALANCE_H
#define BST_PROXY_BALANCE_H

#include "http/stream.h"
#include "proxy/upstream.h"

typedef struct bst_pick_ctx {
	bst_stream *s; /* the request: `hash` keys are evaluated on it (NULL in tests) */
} bst_pick_ctx;

/* The peer for this request with its current address in *addr, or NULL when none can take it. */
const bst_peer *bst_balance_pick(const bst_cfg_upstream *u, const bst_pick_ctx *ctx,
				 bst_sockaddr *addr);

#endif

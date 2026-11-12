/* The upstream model (architecture section 5, "upstream_state"). An `upstream` block, or the
 * implicit one `proxy http://host:port` makes, holds servers; each server becomes one or more
 * peers, the concrete addresses traffic goes to.
 *
 * A server written as an IP literal is one peer. A host name without `resolve` is resolved once,
 * when the configuration loads (in master, before any sandbox), and becomes one peer per address;
 * a name that does not resolve is a load error. A host name with `resolve` gets
 * BST_UP_RESOLVE_SLOTS peers whose addresses the helper fills from DNS and keeps fresh within the
 * record's TTL (clamped by resolver_ttl_min and resolver_ttl_max): a worker never resolves.
 *
 * Shared state. Every peer owns one slot of a shared region master maps before forking (the
 * upstream_state region), with a sequence counter per slot: the helper writes an address under
 * an odd count, workers read it lock-free and retry while the count is odd or moved. A per-region
 * generation counter tells a worker anything changed. Later tasks keep health in the same slots. */
#ifndef BST_PROXY_UPSTREAM_H
#define BST_PROXY_UPSTREAM_H

#include "config/compile.h"
#include "core/addr.h"
#include "io/loop.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_UP_RESOLVE_SLOTS 8 /* addresses a `resolve` server may have at once */

/* One `server` statement. */
typedef struct bst_up_server {
	const char *host; /* as written: an IP literal or a host name */
	uint16_t port;
	unsigned weight;
	unsigned max_conns; /* per worker, 0 = no limit */
	bool backup;
	bool resolve;
	size_t first_peer, npeers; /* its peers in the upstream's array */
	bst_cfg_loc loc;
} bst_up_server;

/* One address traffic may go to. */
typedef struct bst_peer {
	bst_sockaddr addr; /* static peers; a dynamic one reads its slot (bst_peer_addr) */
	unsigned weight;
	unsigned max_conns;
	bool backup;
	bool dynamic;	    /* filled by the helper from DNS */
	size_t state;	    /* its slot in the shared upstream_state region */
	size_t server;	    /* index of its bst_up_server */
} bst_peer;

typedef struct bst_cfg_upstream {
	const char *name;
	bst_cfg_loc loc;
	bool implicit; /* made by `proxy <url>`: name is the URL's host:port */
	bool tls;      /* an https:// URL (Task 6) */
	bst_up_server *servers;
	size_t nservers, servers_cap_;
	bst_peer *peers; /* built by the post hook */
	size_t npeers;
	/* Connection pool (proxy/pool.c), per worker. */
	unsigned keepalive;	       /* idle connections kept per worker, 0 = none */
	uint64_t keepalive_timeout_ms; /* an idle connection closes after this */
	unsigned keepalive_requests;   /* requests one connection carries */
	uint64_t connect_timeout_ms;
	uint64_t send_timeout_ms;
	uint64_t read_timeout_ms;
	size_t index; /* in global.upstreams */
} bst_cfg_upstream;

/* The documented defaults, shared by the directive table and the implicit upstream. */
#define BST_UP_KEEPALIVE 32u
#define BST_UP_KEEPALIVE_TIMEOUT_MS 60000u
#define BST_UP_KEEPALIVE_REQUESTS 1000u
#define BST_UP_CONNECT_TIMEOUT_MS 5000u
#define BST_UP_SEND_TIMEOUT_MS 60000u
#define BST_UP_READ_TIMEOUT_MS 60000u
/* Fills the pool and timeout fields with the defaults above. */
void bst_upstream_defaults(bst_cfg_upstream *u);

/* The upstream called name, or NULL. */
bst_cfg_upstream *bst_upstream_find(const bst_cfg_global *g, const char *name, size_t len);

/* ---- shared state ---- */

typedef struct bst_upstate_slot {
	_Alignas(64) atomic_uint seq; /* odd while the helper writes */
	bst_sockaddr addr;
	uint8_t valid;
} bst_upstate_slot;

/* Slots the configuration needs (the sum of every upstream's peers); 0 means no region. */
size_t bst_upstate_nslots(const bst_config *cfg);
/* Master, before forking: maps the region and fills the static peers' slots. 0, or -1 with err
 * set. A no-op for a configuration with no upstream. The mapping is inherited by every child. */
int bst_upstate_setup(const bst_config *cfg, bst_err *err);
/* The region's generation: it moves whenever any slot changes. */
unsigned bst_upstate_gen(void);
/* Reads a peer's address: true with *out filled when it has one now. */
bool bst_peer_addr(const bst_peer *p, bst_sockaddr *out);
/* Helper side: publishes the addresses of a `resolve` server (at most BST_UP_RESOLVE_SLOTS are
 * used) and clears its other slots. */
void bst_upstate_publish(const bst_cfg_upstream *u, const bst_up_server *srv, const bst_ip *ips,
			 size_t n);

/* ---- the resolver in the helper ---- */

/* Starts resolving every `resolve` server on the helper's loop. Does nothing without one. */
void bst_resolver_helper_start(bst_loop *l, const bst_config *cfg);

#ifdef BST_TEST
/* Test builds only: a test can map the region itself (no master). */
void bst_upstate_test_reset(void);
#endif

#endif

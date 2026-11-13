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
	uint64_t slow_start_ms; /* slow_start=: ramp after recovering, 0 = none */
	size_t first_peer, npeers; /* its peers in the upstream's array */
	bst_cfg_loc loc;
} bst_up_server;

/* One address traffic may go to. */
typedef struct bst_peer {
	bst_sockaddr addr; /* static peers; a dynamic one reads its slot (bst_peer_addr) */
	unsigned weight;
	unsigned max_conns;
	uint64_t slow_start_ms;
	bool backup;
	bool dynamic;	    /* filled by the helper from DNS */
	size_t state;	    /* its slot in the shared upstream_state region */
	size_t server;	    /* index of its bst_up_server */
} bst_peer;

typedef enum bst_balance_algo {
	BST_BAL_ROUND_ROBIN = 0, /* smooth weighted */
	BST_BAL_LEAST_CONN,
	BST_BAL_HASH,
	BST_BAL_PEAK_EWMA,
} bst_balance_algo;

/* `health_check` (proxy/health.c): active probes the helper sends, one per interval for the
 * whole server whatever the number of workers. */
typedef struct bst_up_health {
	bool on;
	const char *path;
	uint64_t interval_ms, timeout_ms;
	unsigned fails, passes;	   /* consecutive results that mark a peer down or up again */
	unsigned expect_lo, expect_hi; /* the status range that passes */
} bst_up_health;

/* `passive_eject`: workers count failures of real requests; fails 0 = off. */
typedef struct bst_up_passive {
	unsigned fails;
	uint64_t window_ms, for_ms;
} bst_up_passive;

/* `retry` (proxy/retry.c). */
#define BST_RETRY_ON_ERROR 1u	/* connection refused, reset or closed before a response */
#define BST_RETRY_ON_TIMEOUT 2u /* connect or first-byte timeout */
#define BST_RETRY_ON_5XX 4u	/* a 502, 503 or 504 response head (not yet sent on) */
typedef struct bst_up_retry {
	bool set;
	unsigned attempts;   /* extra tries, each on a peer not tried yet */
	unsigned budget_pct; /* retries may add at most this share of requests */
	unsigned on;	     /* BST_RETRY_ON_* */
	uint64_t timeout_ms; /* no new try once the request is this old; 0 = none */
} bst_up_retry;

/* `circuit_breaker` (proxy/breaker.c), per worker; 0 = no limit. */
typedef struct bst_up_breaker {
	unsigned max_pending; /* requests waiting for a response head */
	unsigned max_active;  /* requests in flight */
	unsigned max_retries; /* retries in flight */
	unsigned fails;	      /* consecutive failures that open the breaker; 0 = never */
	uint64_t for_ms;      /* how long it stays open before a half-open probe */
} bst_up_breaker;

typedef struct bst_cfg_upstream {
	const char *name;
	bst_cfg_loc loc;
	bool implicit; /* made by `proxy <url>`: name is the URL's host:port */
	bool tls;      /* an https:// URL, or a `tls ...` line in the block (proxy/up_tls.h) */
	struct {
		bool no_verify;	 /* tls verify off */
		const char *ca;	 /* NULL: the system's bundle */
		const char *sni; /* NULL: the server's host */
		const char *cert, *key;
		int min_ver, max_ver; /* 0: TLS 1.2 to TLS 1.3 */
		bst_cfg_loc loc;      /* the first tls line */
		void *ctx;	      /* SSL_CTX, built by bst_uptls_setup */
	} tlsc;
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
	/* `balance` (proxy/balance.c) */
	bst_balance_algo balance;
	const struct bst_tpl *hash_key;
	bool hash_consistent;
	/* resilience (Task 5) */
	bst_up_health health;
	bst_up_passive passive;
	bst_up_retry retry;
	bst_up_breaker breaker;
	unsigned panic_pct; /* panic_threshold: below this share of healthy primaries, ignore health */
	/* `protocol http2` (proxy/client_h2.h): requests go out as streams of HTTP/2 connections */
	bool h2;
	unsigned h2_max_streams; /* max_upstream_h2_streams: per connection */
	/* `send_proxy_protocol v1|v2` (proxy/proxyproto.h): 0 off, else the version. Every request
	 * then gets a connection of its own, never pooled, since the header names one client. */
	unsigned send_pp;
	bst_cfg_loc send_pp_loc;
	size_t index; /* in global.upstreams */
} bst_cfg_upstream;

/* The documented defaults, shared by the directive table and the implicit upstream. */
#define BST_UP_KEEPALIVE 32u
#define BST_UP_KEEPALIVE_TIMEOUT_MS 60000u
#define BST_UP_KEEPALIVE_REQUESTS 1000u
#define BST_UP_CONNECT_TIMEOUT_MS 5000u
#define BST_UP_SEND_TIMEOUT_MS 60000u
#define BST_UP_READ_TIMEOUT_MS 60000u
#define BST_UP_H2_MAX_STREAMS 100u
/* Fills the pool and timeout fields with the defaults above. */
void bst_upstream_defaults(bst_cfg_upstream *u);

/* The upstream called name, or NULL. */
bst_cfg_upstream *bst_upstream_find(const bst_cfg_global *g, const char *name, size_t len);

/* ---- shared state ---- */

typedef struct bst_upstate_slot {
	_Alignas(64) atomic_uint seq; /* odd while the helper writes */
	bst_sockaddr addr;
	uint8_t valid;
	atomic_uint down; /* non-zero: failed its active health checks */
	_Atomic uint64_t eject_until; /* passive ejection: down until this monotonic ms */
	atomic_uint pfails;	      /* passive failures in the current window */
	_Atomic uint64_t pwin;	      /* when that window started */
} bst_upstate_slot;

/* The monotonic clock in milliseconds (the same in every process). */
uint64_t bst_mono_ms(void);
/* The peer may take traffic as far as health goes (always true without a shared region). */
bool bst_peer_up(const bst_peer *p);
/* Marks a peer down or up again (active health); the generation moves. */
void bst_peer_set_down(const bst_peer *p, bool down);
/* Passive ejection, written by any worker: a failure of a real request. True when this one
 * ejected the peer (fails within window_ms keep it out for for_ms). */
bool bst_peer_passive_fail(const bst_peer *p, const bst_up_passive *cfg, uint64_t now);
/* Some peer of u has an address now (so a NULL pick means none is healthy, not unresolved). */
bool bst_upstream_any_addr(const bst_cfg_upstream *u);

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
/* A private region of n slots, all valid and up (unit tests of balancing and health). */
void bst_upstate_test_map(size_t n);
#endif

#endif

/* Upstream connections of one worker: connecting (with connect_timeout), and keeping idle ones for
 * reuse (`keepalive`, `keepalive_timeout`, `keepalive_requests`). Each worker is a process with
 * one loop, so the pool is that process's own and needs no lock.
 *
 * An idle connection is watched for readability: an upstream that closes it, or sends anything
 * while no request is out, has it closed at once (a stale connection is never handed out for a
 * request that may then fail). That leaves the race of a close arriving while the request is
 * being written; the caller retries that case on a fresh connection when it is safe
 * (proxy/handler.c). */
#ifndef BST_PROXY_POOL_H
#define BST_PROXY_POOL_H

#include "core/addr.h"
#include "core/chain.h"
#include "io/loop.h"
#include "io/net.h"
#include "io/sock.h"
#include "proxy/upstream.h"

struct bst_uptls;

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bst_upconn bst_upconn;
/* err 0: connected; else a negative errno (-ETIMEDOUT for connect_timeout). On failure the
 * connection is already gone. */
typedef void (*bst_pool_cb)(void *ud, bst_upconn *c, int err);

struct bst_upconn {
	bst_sock *sk;
	bst_loop *loop;
	const bst_cfg_upstream *up;
	const bst_peer *peer;
	bst_sockaddr addr;
	unsigned requests; /* requests this connection carried before the current one */
	bool idle, connecting;
	bst_timer timer; /* connect timeout, then idle timeout */
	bst_pool_cb cb;
	void *ud;
	bst_upconn *next, *prev; /* the idle list */
	struct bst_uptls *tls;	 /* a TLS upstream: the handshake is done before cb runs */
	/* A PROXY protocol header written right after connect, before TLS (bst_pool_get_pp). Such
	 * a connection names one client, so it is never kept idle. */
	uint8_t pp[112];
	uint8_t pplen;
};

/* I/O on an upstream connection, plain or TLS alike (same contracts as bst_io_recv_start,
 * bst_io_recv_stop and bst_io_send). */
int bst_upconn_recv_start(bst_upconn *c, bst_recv_cb cb, void *ud);
int bst_upconn_recv_stop(bst_upconn *c);
int bst_upconn_send(bst_upconn *c, bst_chain *ch, bst_done_cb cb, void *ud);

/* An idle connection to addr of this peer when there is one: returns 1 and sets *out (cb is not
 * called). Otherwise starts a connection and returns 0: cb runs later, never from inside this
 * call. fresh skips the idle ones (a retry after a stale one failed). A negative errno when not
 * even a socket could be made. */
int bst_pool_get(bst_loop *l, const bst_cfg_upstream *u, const bst_peer *peer,
		 const bst_sockaddr *addr, bool fresh, bst_pool_cb cb, void *ud, bst_upconn **out);
/* A new connection (never an idle one) that starts with the PROXY header pp[0..pplen), at most
 * sizeof ((bst_upconn *)0)->pp bytes; otherwise as bst_pool_get returning 0. */
int bst_pool_get_pp(bst_loop *l, const bst_cfg_upstream *u, const bst_peer *peer,
		    const bst_sockaddr *addr, const void *pp, size_t pplen, bst_pool_cb cb, void *ud);
/* Back after a complete exchange: kept idle when the upstream's keepalive allows, else closed. The
 * connection must have no operation outstanding and its recv stream stopped. */
void bst_pool_put(bst_upconn *c);
/* Closes it (also a connecting one: cb then never runs). */
void bst_pool_close(bst_upconn *c);
/* Connections of this worker open to the peer, idle ones excluded. */
unsigned bst_pool_active(const bst_peer *peer);
/* Idle connections of this worker to the upstream. */
size_t bst_pool_idle(const bst_cfg_upstream *u);

#ifdef BST_TEST
extern unsigned long bst_test_pool_connects; /* connections started by this process */
#endif

#endif

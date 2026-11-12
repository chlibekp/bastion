/* The QUIC endpoint of one `http3` listener in one worker (Phase 8 Task 3, architecture section 4).
 *
 * Every worker has its own UDP socket in the listener's SO_REUSEPORT group (io/listener.h) and its
 * own endpoint on it: the connections it holds, in a per-worker table keyed by connection ID, and
 * their timers on the worker's loop (the Phase 1 wheel). The IDs it issues carry its slot
 * (http/h3/cid.h), so the sk_reuseport program brings every later packet back here.
 *
 * What a datagram for no known connection gets, all without connection state:
 *   - a long header of a version not served: Version Negotiation, only for a datagram of at least
 *     1200 bytes, and always smaller than it (no amplification);
 *   - an Initial in a datagram under 1200 bytes, any other long header, or garbage: dropped;
 *   - an Initial past quic_max_connections: one small CONNECTION_CLOSE(CONNECTION_REFUSED);
 *   - an Initial that must prove its address first (quic_retry always, or auto with more than
 *     quic_retry_threshold handshakes half open): a Retry carrying a token (token.h);
 *   - an Initial with an invalid Retry token: CONNECTION_CLOSE(INVALID_TOKEN);
 *   - a short header: a stateless reset (quic_stateless_reset on), smaller than the packet.
 * An Initial that passes becomes a connection. ngtcp2 holds an unvalidated address to 3x the
 * bytes it received (RFC 9000 section 8.1) until the handshake validates it; a valid Retry or
 * NEW_TOKEN token validates it at once. A ClientHello that does not start in the first Initial
 * makes ngtcp2 ask for a Retry (NGTCP2_ERR_RETRY), which is sent whatever quic_retry says
 * (spikes/quic/README.md finding 3, docs/conformance.md).
 *
 * Lifetime. A connection is freed when its idle or handshake timer fires, at the end of its
 * closing or draining period (3 PTO), or at once when ngtcp2 says to drop it. Each live
 * connection counts as one of the worker's connections (bst_worker_conn_opened), so a graceful
 * stop waits for it; bst_quic_endpoint_drain closes them all.
 *
 * Application data. HTTP/3 (h3_bridge.h) runs on every connection of an endpoint that has its
 * listener's servers (bst_quic_ep_cfg.set); the TLS handshake is visible to requests through the QUIC
 * kind of bst_transport (tls/conn.h), whose SNI moves it to the named server's QUIC context. Without
 * a set (tests, fuzzing) stream data is consumed and discarded, with its credit given back.
 *
 * Sending. Packets go through one queue per endpoint (bst_udp_send allows one send in flight per
 * socket): txq.h, which batches a connection's back-to-back packets into GSO sends. A connection
 * that finds the queue full stops writing and resumes when a send completes; nothing is lost that
 * ngtcp2 would not retransmit. With quic_pacing a connection writes at most ngtcp2's send quantum
 * per turn and the rest when its pacing time comes (the expiry arm() follows). ECN marks go both
 * ways under quic_ecn; quic_mtu_discovery sets DF on the socket (IP_PMTUDISC_PROBE) for ngtcp2's
 * path MTU probes. */
#ifndef BST_H3_QUIC_H
#define BST_H3_QUIC_H

#include "config/compile.h"
#include "core/addr.h"
#include "core/err.h"
#include "http/h3/token.h"
#include "io/loop.h"
#include "io/net.h"
#include "io/udp.h"
#include "route/vhost.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_QUIC_PKT_MAX 1500u	   /* bytes of one packet ngtcp2 writes */
#define BST_QUIC_UDP_BUFS 64u	   /* bst_loop_cfg.uring_udp_bufs of a worker with an http3 listener */

typedef struct bst_quic_endpoint bst_quic_endpoint;
typedef struct bst_quic_conn bst_quic_conn;
typedef struct bst_worker bst_worker;

/* Master, before any fork: counters, and ngtcp2's OpenSSL backend. */
void bst_quic_init(void);

/* Starts the endpoint of listener socket s (bound, in its reuseport group) in worker w with the
 * figures q of the listener's default server: bst_udp_start on s, so before the sandbox. Logs at
 * info level when UDP runs on the readiness path (recvmmsg) instead of the io_uring ring, and why.
 * NULL with err set. */
bst_quic_endpoint *bst_quic_endpoint_start(bst_worker *w, bst_sock *s, const bst_listener_set *set,
					   const bst_cfg_quic *q, bst_err *err);

/* Graceful stop: stops receiving; an HTTP/3 connection gets GOAWAY and closes (H3_NO_ERROR) once its
 * requests in flight finished, any other one is closed at once; each is freed after its closing
 * period. */
void bst_quic_endpoint_drain(bst_quic_endpoint *ep);

typedef struct bst_quic_stats {
	uint64_t live;	     /* connections held, closing ones included */
	uint64_t half_open;  /* of those, handshake not complete */
	uint64_t opened, closed;
	uint64_t retries, vn, resets, refused, dropped;
} bst_quic_stats;
void bst_quic_endpoint_stats(const bst_quic_endpoint *ep, bst_quic_stats *out);

/* ---- the endpoint without a socket: tests and fuzzing ---- */

/* Where packets go instead of a socket: called once per packet, data valid during the call. */
typedef void (*bst_quic_sink)(void *ud, const bst_udp_pkt *pkt);

typedef struct bst_quic_ep_cfg {
	bst_loop *loop;
	const bst_cfg_quic *q;	   /* ssl_ctx must be set */
	uint16_t slot;		   /* the worker slot the endpoint's connection IDs carry */
	bst_sockaddr local;	   /* the socket's address, for datagrams without IP_PKTINFO */
	bst_quic_secrets secrets;
	bst_worker *worker;	   /* NULL: no connection accounting */
	const bst_listener_set *set; /* the listener's servers; NULL: no HTTP/3, stream data dropped */
	bst_quic_sink sink;	   /* NULL: the socket given to bst_quic_endpoint_attach_ */
	void *sink_ud;
} bst_quic_ep_cfg;

bst_quic_endpoint *bst_quic_endpoint_new(const bst_quic_ep_cfg *cfg, bst_err *err);
/* One datagram (one GRO segment). ecn is the IP ECN bits. */
void bst_quic_endpoint_input(bst_quic_endpoint *ep, const uint8_t *data, size_t len,
			     const bst_sockaddr *src, const bst_sockaddr *dst, uint8_t ecn);
/* Frees every connection and the endpoint; nothing is sent. */
void bst_quic_endpoint_free(bst_quic_endpoint *ep);

#endif

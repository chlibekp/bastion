/* Batched UDP I/O on loop sockets, with GSO, GRO, source-address selection and ECN
 * (architecture section 3; HTTP/3 in Phase 8 runs on it). Callbacks run on the loop thread.
 * Errors are negative errno values (0 is success), as in net.h, and the lifetime rules of
 * net.h apply: bst_sock_close cancels everything, no callback runs after it returns (nor
 * after bst_udp_stop for the receive side), and a send in flight when the socket is closed
 * completes silently.
 *
 * The socket is an AF_INET or AF_INET6 SOCK_DGRAM socket the caller made, bound or not,
 * wrapped with bst_sock_wrap. bst_udp_start sets IP_PKTINFO, IPV6_RECVPKTINFO, IP_RECVTOS
 * and IPV6_RECVTCLASS (both families on an AF_INET6 socket, so v4-mapped traffic carries
 * them too), UDP_GRO when asked, and learns whether the kernel does UDP_SEGMENT. The
 * options udp_gso, udp_gro and rcvbuf are the fields of bst_udp_cfg; their directives are
 * registered in Phase 8, where QUIC listeners are configured.
 *
 * Receive. One stream per socket. The callback gets a batch of datagrams, each with its
 * own buffer (one reference, the callback unrefs it; do so before bst_loop_free), source,
 * destination (the local address it arrived on, for replies), interface, ECN bits and, for
 * a GRO-coalesced buffer, the segment size. msgs is valid only during the call. Datagrams
 * that cannot be delivered whole are dropped and counted (bst_udp_stats): zero-length ones,
 * ones longer than the buffer (kernel MSG_TRUNC, or on io_uring a datagram longer than the
 * limit the epoll buffer would have had), ones whose control data was truncated. A
 * datagram of exactly the limit is delivered whole. A GRO segment size of 0 or at least the
 * datagram length means "not coalesced" and is reported as gro_segment_size 0.
 * (NULL, 0, -errno) ends the stream (call bst_udp_start again for more). ICMP errors on a
 * connected socket (ECONNREFUSED, ...) are not stream errors. Datagrams in flight when the
 * stream is stopped are dropped: UDP is lossy and a stop loses nothing a sender could rely on.
 *
 * Holding buffers never stalls other sockets, on either backend. epoll receives into
 * per-socket scratch buffers and hands out a right-sized copy (up to
 * BST_UDP_COPY_MAX bytes) or the scratch buffer itself, replaced at once. io_uring copies
 * out of the ring under the same rule as TCP (small payload, or half the slots out).
 *
 * Buffer size and memory. max_dgram (default BST_UDP_MAX_DGRAM) bounds a datagram without
 * GRO. With GRO a coalesced datagram can reach 64 KiB, so buffers are BST_UDP_GRO_BUF
 * (64 KiB) then: epoll costs BST_UDP_BATCH * 64 KiB = 4 MiB of address space per GRO
 * socket (pages are touched as datagrams arrive). On io_uring the ring's 16 KiB slots would
 * truncate, so UDP has its own provided-buffer group with slots of BST_UDP_SLOT_SIZE
 * (64 KiB + room for the name and control data), bst_loop_cfg.uring_udp_bufs of them per
 * loop: 64 slots cost about 4.1 MiB, allocated at loop creation and not before, because the
 * restricted ring registers nothing afterwards. With uring_udp_bufs 0, or a kernel without
 * multishot RECVMSG (6.0, probed like multishot recv), UDP on io_uring uses readiness
 * (POLL_ADD) and recvmmsg, exactly as on epoll: same results, no ring slots.
 *
 * Send. bst_udp_send sends n packets in order and calls done exactly once, never from
 * inside the call, with the payload bytes sent (all of it when err is 0). One send at a
 * time per socket: a second one, while the first has not called done, returns -EBUSY.
 * pkts and the memory behind data must stay valid until done runs (or the socket is
 * closed, after which the module no longer touches them). A packet with gso_size > 0 and
 * len > gso_size is one GSO send of len/gso_size segments (UDP_SEGMENT), at most 64
 * segments and 65507 bytes; if GSO is off or unsupported it goes as plain datagrams of
 * gso_size, so the peer sees the same datagrams. EIO from a GSO send turns GSO off for the
 * socket and resends that packet as plain datagrams: whatever already went out is not sent
 * again, nothing is lost. EAGAIN waits for POLLOUT (a full socket never fails the send)
 * and the rest goes in order. Any other error ends the send: the packets not yet sent are
 * not sent, done gets the error and the bytes that did go out. ecn sets the packet's ECN
 * bits (the socket's IP_TOS DSCP is kept); src selects the source address (IP_PKTINFO,
 * IPV6_PKTINFO) when its family is set. Epoll sends with sendmmsg, io_uring with chained
 * SENDMSG. At most BST_UDP_SEND_BUDGET datagrams go out per readiness event or round
 * before other sockets get their turn. */
#ifndef BST_IO_UDP_H
#define BST_IO_UDP_H

#include "core/addr.h"
#include "core/buf.h"
#include "io/net.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_UDP_BATCH 64u          /* datagrams per recvmmsg/sendmmsg and per callback batch */
#define BST_UDP_RECV_BUDGET 256u   /* datagrams per wakeup before yielding to other sockets */
#define BST_UDP_SEND_BUDGET 256u   /* datagrams per wakeup (epoll) or round (io_uring) */
#define BST_UDP_MAX_DGRAM 2048u    /* default cfg.max_dgram */
#define BST_UDP_COPY_MAX 2048u     /* payloads up to this size are copied, never hold a slot */
#define BST_UDP_GRO_BUF 65536u     /* buffer size with GRO */
#define BST_UDP_SLOT_SIZE (65536u + 512u) /* io_uring slot: payload plus record header, name, control */
#define BST_UDP_SEND_MAX_LEN 65507u /* largest datagram or GSO send */
#define BST_UDP_GSO_SEGS 64u       /* UDP_MAX_SEGMENTS */

typedef struct bst_udp_cfg {
	bool gso;            /* udp_gso: use UDP_SEGMENT when the kernel has it */
	bool gro;            /* udp_gro: receive coalesced datagrams (UDP_GRO) when the kernel has it */
	unsigned rcvbuf;     /* rcvbuf: SO_RCVBUF in bytes, 0 = leave the socket's */
	size_t max_dgram;    /* largest datagram without GRO, 0 = BST_UDP_MAX_DGRAM */
} bst_udp_cfg;

typedef struct bst_udp_msg {
	bst_buf *buf;                /* payload, len > 0; the callback owns the reference */
	bst_sockaddr src;
	bst_sockaddr dst;            /* local address it arrived on; dst.ip.family 0 if unknown */
	uint32_t ifindex;            /* interface it arrived on, 0 if unknown */
	uint8_t ecn;                 /* 0 not-ECT, 1 ECT(1), 2 ECT(0), 3 CE */
	uint16_t gro_segment_size;   /* > 0: buf holds segments of this size (the last may be shorter) */
} bst_udp_msg;

/* n > 0 datagrams with err 0; (NULL, 0, -errno) ends the stream. */
typedef void (*bst_udp_recv_cb)(void *ud, bst_udp_msg *msgs, int n, int err);

typedef struct bst_udp_pkt {
	const void *data;
	size_t len;           /* > 0 */
	uint16_t gso_size;    /* 0: plain datagram */
	bst_sockaddr dst;
	bst_ip src;           /* family 0: let the kernel choose */
	uint32_t src_ifindex; /* with src, 0 = any (needed only for link-local IPv6) */
	uint8_t ecn;          /* 0..3 */
} bst_udp_pkt;

typedef struct bst_udp_stats {
	uint64_t rx_dgrams;    /* delivered */
	uint64_t rx_trunc;     /* dropped: longer than the buffer (MSG_TRUNC) */
	uint64_t rx_empty;     /* dropped: zero length */
	uint64_t rx_badctl;    /* dropped: control data truncated or source not IP */
	uint64_t rx_nomem;     /* dropped: no buffer for the copy */
	uint64_t tx_msgs;      /* datagrams or GSO sends handed to the kernel */
	uint64_t tx_gso_msgs;  /* of those, GSO */
	uint64_t gso_fallbacks; /* times EIO turned GSO off (0 or 1) */
	bool gso;              /* GSO is in use now */
	bool gro;              /* GRO is on */
	bool ring;             /* receive runs on multishot RECVMSG (io_uring) */
} bst_udp_stats;

/* Attaches UDP state on first use (cfg applies then, NULL = defaults) and starts the
 * receive stream. -EBUSY while one runs, -EINVAL for a socket that is not UDP over IP,
 * -ENOMEM. Later starts keep the first cfg. */
int bst_udp_start(bst_sock *s, const bst_udp_cfg *cfg, bst_udp_recv_cb cb, void *ud);
/* Stops receiving; immediate, no callback afterwards. Sends are unaffected. 0. */
int bst_udp_stop(bst_sock *s);
/* -EINVAL: bad packet (len 0, GSO over the limits, ecn > 3, family mismatch) or bst_udp_start
 * not called; -EBUSY: a send is in flight; 0: done will run. */
int bst_udp_send(bst_sock *s, const bst_udp_pkt *pkts, int n, bst_done_cb cb, void *ud);
void bst_udp_stats_get(const bst_sock *s, bst_udp_stats *out);

/* Walks the segments of a received datagram: returns the length of the segment at *off and
 * advances *off, with *seg pointing at it; 0 when none is left. A datagram with
 * gro_segment_size 0 is one segment. */
size_t bst_udp_segment(const bst_udp_msg *m, size_t *off, const unsigned char **seg);

#ifdef BST_TEST
extern unsigned bst_test_udp_gso_eio;   /* the next N GSO sends fail with EIO instead of going out */
extern unsigned bst_test_udp_send_limit; /* nonzero: at most this many datagrams per sendmmsg or chain */
extern unsigned bst_test_udp_eagain;    /* the next N send rounds find the socket full (EAGAIN) */
extern unsigned bst_test_udp_rounds;    /* send rounds run (loop thread) */
extern unsigned bst_test_udp_budget;    /* nonzero: replaces BST_UDP_RECV_BUDGET */
#endif

#endif

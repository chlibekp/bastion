/* The send queue of one QUIC endpoint (Phase 8 Task 5): packets batched for UDP GSO.
 *
 * bst_udp_send allows one send in flight per socket, so every connection of an endpoint shares
 * one queue: a ring of BST_TXQ_SLOTS batches. A batch is one bst_udp_pkt, so one sendmsg: up
 * to BST_TXQ_SEGS packets of one connection, back to back, for the same destination, source
 * and ECN marks, all of the batch's segment size except possibly the last, which ends it (the
 * rule of UDP_SEGMENT). With GSO the kernel cuts it into datagrams; without it (quic_gso off,
 * a kernel without UDP_SEGMENT, or after an EIO turned it off, see io/udp.h) bst_udp_send
 * sends the same datagrams one by one, so the peer sees the same packets either way.
 *
 * Writing. A writer checks bst_txq_room, has ngtcp2 write one packet into bst_txq_scratch and
 * hands it to bst_txq_add, which copies it into the open batch when it fits there, else into
 * a new one. bst_txq_end closes the open batch (one connection's turn is over); bst_txq_kick
 * sends what is closed. A packet added `alone` (a path MTU probe, larger than the path is known
 * to carry) gets a batch and a send of its own: if the path refuses it (EMSGSIZE), nothing
 * else goes down with it.
 *
 * When a send completes the queue calls on_room so that writers it turned away can go on. A
 * failed send drops what it had not sent: QUIC detects the loss and sends the data again.
 *
 * Without a socket (tests, fuzzing) the sink gets every packet, one call per datagram, at
 * bst_txq_kick. */
#ifndef BST_H3_TXQ_H
#define BST_H3_TXQ_H

#include "core/addr.h"
#include "io/net.h"
#include "io/udp.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_TXQ_SLOTS 128u	/* batches queued per endpoint */
#define BST_TXQ_SEGS 16u	/* packets per batch (GSO segments), at most BST_UDP_GSO_SEGS */
#define BST_TXQ_PKT_MAX 1500u	/* bytes of one packet */

/* Called once per datagram when there is no socket; data valid during the call. */
typedef void (*bst_txq_sink)(void *ud, const bst_udp_pkt *pkt);

typedef struct bst_txq_stats {
	uint64_t pkts;	      /* packets added */
	uint64_t batches;     /* batches handed to bst_udp_send (or the sink) */
	uint64_t multi;	      /* of those, with more than one packet */
	uint64_t send_errors; /* sends that ended with an error, their unsent packets dropped */
} bst_txq_stats;

typedef struct bst_txq_batch {
	bst_udp_pkt meta; /* data, len (all segments), gso_size (0: one packet), dst, src, ecn */
	uint16_t seg;	  /* segment size: the first packet's length */
	uint16_t nseg;
	bool alone;
	bool closed;	  /* nothing more joins it */
	uint8_t data[BST_TXQ_SEGS * BST_TXQ_PKT_MAX];
} bst_txq_batch;

typedef struct bst_txq {
	bst_sock *sock;	      /* NULL: the sink */
	bst_txq_sink sink;
	void *sink_ud;
	void (*on_room)(void *ud); /* a send completed: there may be room again */
	void *room_ud;
	unsigned max_segs;    /* BST_TXQ_SEGS, or 1 with quic_gso off */
	bst_txq_batch *slots;
	size_t head, count, inflight; /* [head, head+inflight) is in bst_udp_send */
	bool open;	      /* the last batch still takes packets */
	bst_udp_pkt sendv[BST_UDP_BATCH];
	uint8_t scratch[BST_TXQ_PKT_MAX];
	bst_txq_stats st;
} bst_txq;

/* gso false makes every batch one packet. sock NULL: the sink gets the packets. -1 out of
 * memory. */
int bst_txq_init(bst_txq *q, bst_sock *sock, bool gso, bst_txq_sink sink, void *sink_ud,
		 void (*on_room)(void *), void *room_ud);
void bst_txq_free(bst_txq *q);

/* A packet can be added: a free batch exists, whichever batch the packet ends up in. */
bool bst_txq_room(const bst_txq *q);
/* Where the writer has the next packet written, BST_TXQ_PKT_MAX bytes. */
uint8_t *bst_txq_scratch(bst_txq *q);
/* Copies a packet (len 1..BST_TXQ_PKT_MAX) into the queue; only after bst_txq_room said yes.
 * src NULL or family 0: the kernel chooses. */
void bst_txq_add(bst_txq *q, const uint8_t *data, size_t len, const bst_sockaddr *dst, const bst_ip *src,
		 uint8_t ecn, bool alone);
/* Closes the open batch. */
void bst_txq_end(bst_txq *q);
/* Sends the closed batches, unless a send is in flight (its completion sends the rest). */
void bst_txq_kick(bst_txq *q);

#endif

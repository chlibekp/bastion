/* UDP internals shared by udp.c (API, readiness path, control messages, send planning) and
 * uring_udp.c (multishot RECVMSG and chained SENDMSG). Not for use outside src/io/, except
 * by the unit test of the control-message parser. */
#ifndef BST_IO_UDP_PRIV_H
#define BST_IO_UDP_PRIV_H

#include "io/loop_priv.h"
#include "io/udp.h"

#include <sys/socket.h>
#include <sys/uio.h>

#define BST_UDP_CTL 256u  /* receive control-data space per datagram */
#define BST_UDP_SCTL 128u /* send control-data space per message */
#define BST_UDP_CHAIN 16u /* SENDMSG SQEs per io_uring round */
#define BST_UDP_RNAME sizeof(struct sockaddr_in6) /* name space of a RECVMSG record */

#ifdef BST_TEST
extern unsigned bst_test_udp_ctl_cap; /* nonzero: receive control space (forces MSG_CTRUNC) */
#define BST_UDP_RCTL (bst_test_udp_ctl_cap != 0 ? bst_test_udp_ctl_cap : BST_UDP_CTL)
#define BST_UDP_RBUDGET (bst_test_udp_budget != 0 ? bst_test_udp_budget : BST_UDP_RECV_BUDGET)
#else
#define BST_UDP_RCTL BST_UDP_CTL
#define BST_UDP_RBUDGET BST_UDP_RECV_BUDGET
#endif

#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif

/* What the control data of one datagram said. */
typedef struct bst_udp_meta {
	bst_sockaddr dst;
	bool has_dst;
	uint32_t ifindex;
	uint8_t ecn;
	uint32_t gro; /* UDP_GRO segment size as the kernel gave it (0: none) */
} bst_udp_meta;

/* Walks the control data with bounds checks, tolerating unknown types. False if it is
 * malformed (a header that does not fit); what was read before it is kept. len 0 is fine. */
bool bst_udp_parse_cmsg_(const void *ctl, size_t len, bst_udp_meta *out);
/* Kernel sockaddr to bst_sockaddr (v4-mapped becomes v4); false if too short or not IP. */
bool bst_udp_name_(const void *name, size_t len, bst_sockaddr *out);

/* One message of a send round: its own iovec, address and control data, so the kernel can
 * read them until the round completes. */
typedef struct bst_umsg {
	struct msghdr mh;
	struct iovec iov;
	struct sockaddr_storage addr;
	unsigned char ctl[BST_UDP_SCTL] __attribute__((aligned(8))); /* cmsghdr alignment */
	int pkt;     /* index of its packet */
	size_t off;  /* payload offset in that packet, and length */
	size_t len;
	bool gso;
} bst_umsg;

struct bst_urx; /* epoll-style receive scratch (udp.c) */

typedef struct bst_udp {
	bst_sock *s;
	int family; /* AF_INET or AF_INET6 */
	bool gso, gro;
	size_t cap;     /* receive buffer size; also the longest datagram delivered */
	int base_tos;   /* the socket's TOS or traffic class: DSCP is kept, ECN replaced */
	bst_udp_stats st;
	/* receive */
	bst_udp_recv_cb cb;
	void *cb_ud;
	bool on;
	bool ring_rx;   /* multishot RECVMSG (io_uring), else readiness + recvmmsg */
	struct bst_urx *rx;
	/* send */
	bool send_on;
	const bst_udp_pkt *pk;
	int npk, cur;   /* packet count, and the first packet not completely sent */
	size_t off;     /* bytes of pk[cur] already sent (plain split in progress) */
	size_t bytes;
	int err;
	bool fin;       /* the send ended; done runs from the loop */
	bst_done_cb dcb;
	void *dud;
	bst_umsg m[BST_UDP_BATCH];
	/* io_uring */
	struct msghdr rmh;   /* template of the multishot RECVMSG: lengths of name and control */
	bst_udp_msg pend[BST_UDP_BATCH];
	int npend;
	bst_sock *fnext, *wnext;
	bool flisted, waiting;
	uint16_t us_out;    /* send SQEs in flight */
	int round_k, ok_n, rerr;
	uint16_t park_tag;  /* tag of the multishot cancelled over budget: its carried completions are ours */
	bool park_valid;
	int phase;          /* what the send's SQEs are: 0 none, 1 sendmsg chain, 2 poll, 3 nop */
} bst_udp;

/* Plans up to max messages from the cursor into u->m: GSO packets whole when GSO is on,
 * else plain datagrams of gso_size. Returns the count. */
int bst_udp_plan_(bst_udp *u, int max);
/* The first n planned messages went out: advance the cursor and the counters. */
void bst_udp_advance_(bst_udp *u, int n);
/* EIO from a GSO send: GSO is off for this socket from now on. */
void bst_udp_gso_off_(bst_udp *u);
/* Buffer for a copied payload of len bytes (slab or malloc); NULL on exhaustion. */
bst_buf *bst_udp_copy_buf_(bst_loop *l, size_t len);
/* A buffer for a sub-range of parent's memory; takes over the caller's reference on parent
 * (dropped when the new buffer is). NULL on exhaustion, parent unreffed then too. */
bst_buf *bst_udp_sub_buf_(bst_buf *parent, void *data, size_t len);
/* Fill msg from parsed control data and normalise the GRO size against len. */
void bst_udp_fill_msg_(bst_udp_msg *m, const bst_udp_meta *meta, size_t len);
/* ICMP-derived errors on a connected socket: not a reason to end a stream or a send. */
bool bst_udp_transient_(int e);

/* Hooks from net_common.c and loop.c. */
void bst_udp_ready_(bst_sock *s, int err);       /* recv slot ready */
void bst_udp_send_ready_(bst_sock *s, int err);  /* send slot ready */
void bst_udp_slot_failed_(bst_sock *s, bool recv, int err);
void bst_udp_sock_close_(bst_sock *s);           /* close: drop buffers */
void bst_udp_free_(bst_sock *s);                 /* the socket is freed */

#endif

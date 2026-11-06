/* io_uring backend internals, shared by loop_uring.c (ring, dispatch, polls, wake, drain),
 * uring_net.c (accept, recv), uring_send.c (send, connect) and uring_bufs.c
 * (provided-buffer ring, pipe pool). Also the private interface of Task 4 (setup result)
 * and Task 8 (restrictions). Not for use outside src/io/, except src/proc/sandbox.c for
 * the ring restrictions. */
#ifndef BST_IO_URING_PRIV_H
#define BST_IO_URING_PRIV_H

#include "io/loop_priv.h"

/* liburing's inline helpers do not build under -Wconversion -Wsign-conversion -Wshadow. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <liburing.h>
#pragma GCC diagnostic pop

#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>

#define BST_URING_IOV 64u         /* iovecs per SENDMSG; a longer chain takes several */
#define BST_URING_PIPES 8u        /* idle splice pipes kept per loop for file segments */
#define BST_URING_PIPES_MAX 64u   /* pipes in use per loop; more file sends use sendfile */
#define BST_URING_PIPE_SIZE (64u << 10) /* splice pipe capacity, to be measured (Phase 15) */
#define BST_URING_PIPE_MIN (16u << 10)  /* a smaller pipe (per-user pipe limits) is discarded */
#define BST_URING_DRAIN_MS 1000u  /* bst_loop_free waits this long for cancelled operations */
#define BST_URING_SQPOLL_WAIT_US 1000u /* close waits this long for the SQ thread to take SQEs */
/* Copy-out: a completed recv is copied into a slab buffer and its ring slot recycled at
 * once when its payload is below BST_URING_COPY_MAX bytes, or when at least half the
 * ring's slots are out (in callers' hands or carried), so holding a buffer costs memory,
 * as on epoll, never ring slots other sockets need. */
#define BST_URING_COPY_MAX 2048u
#define BST_URING_BGID 0          /* buffer group of the loop's provided-buffer ring */

/* What a user_data names: kind in the low 4 bits, the socket (16-byte aligned, below
 * 2^48) in bits 4..47, the tag in bits 48..63. */
enum {
	BST_UK_IGNORE,     /* cancel requests: nothing to account */
	BST_UK_WAKE,       /* the eventfd read */
	BST_UK_POLL,       /* bst_io_poll */
	BST_UK_RECV,
	BST_UK_ACCEPT,
	BST_UK_SEND,       /* SENDMSG or SENDMSG_ZC of memory segments */
	BST_UK_SPLICE_IN,  /* file -> pipe */
	BST_UK_SPLICE_OUT, /* pipe -> socket */
	BST_UK_SPOLL,      /* POLLOUT before a splice to a full socket */
	BST_UK_CONNECT,
	BST_UK_NOP,        /* completes an empty send from the loop */
	BST_UK_SFPOLL,     /* POLLOUT before a sendfile (file segments without splice) */
	BST_UK_TEST,       /* injected by tests (BST_TEST only) */
};

/* Features found at setup (bst_uring_features_). Missing ones fall back as noted. */
#define BST_URF_RECV_MSHOT 0x01u   /* multishot recv (6.0), else single-shot recv re-armed */
#define BST_URF_ACCEPT_MSHOT 0x02u /* multishot accept (5.19), else single-shot accept */
#define BST_URF_SENDMSG_ZC 0x04u   /* IORING_OP_SENDMSG_ZC (6.1), else uring_send_zc_min is off */
#define BST_URF_RING_FD 0x08u      /* IORING_REGISTER_RING_FDS (5.18) */
#define BST_URF_NAPI 0x10u         /* IORING_REGISTER_NAPI (6.9) took */

/* One completion, copied out of the CQ ring. copy: a carried recv whose data was copied
 * out of its ring slot (the slot is back in the ring, IORING_CQE_F_BUFFER cleared). */
typedef struct {
	uint64_t ud;
	int32_t res;
	uint32_t flags;
	bst_buf *copy;
} bst_ucqe;

/* A provided-buffer ring slot handed out as a bst_buf (bst_buf_init over this header). */
typedef struct bst_ubuf {
	bst_buf b;
	struct bst_uring *u;
	uint16_t bid;
} bst_ubuf;

typedef struct bst_upipe {
	struct bst_upipe *next;
	int rd, wr;
	size_t cap;
} bst_upipe;

/* Kernel-visible arguments of the send in flight: valid until its SQEs completed. */
typedef struct bst_usend {
	struct msghdr mh;
	struct iovec iov[BST_URING_IOV];
	struct sockaddr_storage addr;
	/* zero-copy: a reference on each buffer behind iov, dropped at the notification, so
	 * the caller's unref (allowed after close) never frees pages the kernel still sends */
	bst_buf *zbuf[BST_URING_IOV];
	unsigned nzbuf;
} bst_usend;

typedef struct bst_uring {
	struct io_uring ring;
	bst_loop *loop;
	unsigned setup_flags; /* IORING_SETUP_* the ladder ended on */
	unsigned kfeat;       /* IORING_FEAT_* */
	unsigned feat;        /* BST_URF_* */
	size_t zc_min;
	int efd;
	uint64_t evbuf;      /* eventfd counter read by the wake SQE */
	bool wake_live;
	bool draining;
	bool leak;           /* drain timed out: memory the kernel may use is never freed */
	bst_ucqe *batch;     /* [0, carry) carried from the last dispatch, then new ones */
	unsigned cap, n, carry;
	uint32_t epoch;      /* dispatch counter */
	uint64_t prepped;    /* SQEs prepared so far */
	unsigned live;       /* counted SQEs waiting for their last completion */
	unsigned koverflow;  /* dropped-CQE counter last seen */
	/* provided buffers */
	struct io_uring_buf_ring *br;
	unsigned char *bmem;
	bst_ubuf *bhdr;
	unsigned nbufs;
	unsigned taken;      /* out of the ring: in a batch, a stash or a caller's hands */
	size_t bout;         /* handed to callers and not yet unreffed */
	bool breturned;      /* a buffer went back since the waiters were last re-armed */
	bst_sock *bwait;     /* recv streams waiting for buffers */
	bst_sock *pend;      /* recv streams with a stash to deliver */
	/* send */
	bst_upipe *pipes;    /* idle, empty pipes */
	unsigned npipes;
	unsigned pipes_used; /* pipes held by sends */
	bst_slab *sends;     /* bst_usend */
	uint64_t *pcan;      /* cancels that found no SQE, retried before each wait */
	unsigned npcan, capcan;
} bst_uring;

/* ---- loop_uring.c ---- */
uint64_t bst_uring_ud_(unsigned kind, const void *p, uint16_t tag);
/* need SQEs in a row (a link), submitting first if the SQ is short; NULL if impossible. */
struct io_uring_sqe *bst_uring_sqe_(bst_uring *u, unsigned need);
/* Tag sqe for s and count it in flight (s->inflight, u->live). */
void bst_uring_prep_(bst_uring *u, struct io_uring_sqe *sqe, unsigned kind, bst_sock *s,
		     uint16_t tag);
/* Ask the kernel to cancel every request with this user_data. False: no SQE now, the
 * cancel waits on the retry list (the caller keeps the fd open meanwhile). */
bool bst_uring_cancel_(bst_uring *u, uint64_t ud);
/* Push prepared SQEs to the kernel now (with SQPOLL: until the SQ thread took them, at
 * most BST_URING_SQPOLL_WAIT_US). False if some are still not taken. */
bool bst_uring_flush_(bst_uring *u);
/* Has s an SQE that the kernel has not picked up yet? */
bool bst_uring_unsubmitted_(bst_uring *u, const bst_sock *s);

/* ---- uring_net.c ---- */
extern const bst_net_ops bst_uring_net_ops_;
/* ---- uring_send.c ---- */
int bst_uring_send_start_(bst_sock *s);
int bst_uring_connect_(bst_sock *s, const struct sockaddr_storage *to, socklen_t len);
void bst_uring_send_kick_(bst_sock *s);
/* Close: cancel the send's SQEs in flight (false: a cancel waits for an SQE), or free its
 * state now if none is. */
bool bst_uring_send_detach_(bst_uring *u, bst_sock *s);

/* Completion of a recv, accept or send-path SQE of s. last: the SQE's final completion. */
void bst_uring_recv_cqe_(bst_uring *u, bst_sock *s, const bst_ucqe *e, bool last);
void bst_uring_accept_cqe_(bst_uring *u, bst_sock *s, const bst_ucqe *e, bool last);
void bst_uring_send_cqe_(bst_uring *u, bst_sock *s, unsigned kind, const bst_ucqe *e, bool last);
/* Close: cancel recv, accept and send, return stashed buffers, schedule cleanup. False if
 * a cancel had to wait for an SQE. */
bool bst_uring_net_detach_(bst_uring *u, bst_sock *s);
/* Dispatch carried a recv completion of s: copy it out of the ring under pressure, and
 * cancel the multishot recv so one socket cannot keep taking slots. */
void bst_uring_net_carry_(bst_uring *u, bst_sock *s, bst_ucqe *e);
/* A carried recv completion of s was handled: re-arm once none is left. */
void bst_uring_net_uncarry_(bst_uring *u, bst_sock *s);
/* Before waiting: re-arm recv streams that waited for buffers, if some came back. */
void bst_uring_net_prewait_(bst_uring *u);
/* Start of dispatch: deliver stashes of restarted streams (counts against the budget). */
void bst_uring_net_pend_(bst_uring *u);
/* bst_loop_free: empty both lists (their holds on sockets are released). */
void bst_uring_net_drain_(bst_uring *u);
/* One more recv or accept completion for s in this dispatch, at most max; false: carry
 * this one and every later one of s to the next dispatch, keeping their order. */
bool bst_uring_budget_(bst_uring *u, bst_sock *s, unsigned max);

/* ---- uring_bufs.c ---- */
int bst_ubufs_init_(bst_uring *u, unsigned n, bst_err *err);
void bst_ubufs_free_(bst_uring *u);
/* The buffer of a completion (bid from its flags), len bytes filled. */
bst_ubuf *bst_ubufs_take_(bst_uring *u, unsigned bid, size_t len);
/* Back to the ring without ever reaching a caller. NULL is ignored. */
void bst_ubufs_recycle_(bst_uring *u, bst_ubuf *b);
/* Hand to a caller: one reference, returned to the ring at its last unref. */
bst_buf *bst_ubufs_hand_(bst_uring *u, bst_ubuf *b);
/* Copy-out: the slot's bytes in a slab buffer (one reference), the slot recycled. NULL
 * if no slab buffer: the caller then hands the slot. */
bst_buf *bst_ubufs_copy_(bst_uring *u, bst_ubuf *b);
/* Is the ring under pressure (half its slots out or more)? */
bool bst_ubufs_pressed_(const bst_uring *u);
unsigned bst_ubufs_avail_(const bst_uring *u);
/* An empty pipe for file segments (pooled or new); NULL with *err = -errno: -EMFILE or
 * -ENFILE, -ENOBUFS (the kernel gave less than BST_URING_PIPE_MIN) or -EBUSY (the
 * per-loop cap of pipes in use) mean "use sendfile". */
bst_upipe *bst_upipe_get_(bst_uring *u, int *err);
/* Back to the pool if empty and the pool has room, else closed. */
void bst_upipe_put_(bst_uring *u, bst_upipe *p, bool empty);
void bst_upipes_free_(bst_uring *u);

/* ---- Task 4: what setup ended with ---- */
unsigned bst_uring_setup_flags_(const bst_loop *l);
unsigned bst_uring_features_(const bst_loop *l);

/* ---- Task 8: restricting the ring ----
 * The ring is created IORING_SETUP_R_DISABLED. When set, this hook runs after every
 * registration and before IORING_REGISTER_ENABLE_RINGS, on the thread creating the loop;
 * nonzero (a negative errno) fails bst_loop_new. The ring needs exactly these opcodes
 * and SQE flags, so a restriction set built from them keeps the backend working. */
extern int (*bst_uring_pre_enable_)(struct io_uring *ring);
extern const uint8_t bst_uring_opcodes_[];
extern const unsigned bst_uring_nopcodes_;
#define BST_URING_SQE_FLAGS (IOSQE_IO_LINK | IOSQE_BUFFER_SELECT)
/* io_uring_register opcodes used after the hook: only teardown (bst_loop_free) needs any. */
extern const uint8_t bst_uring_register_ops_[];
extern const unsigned bst_uring_nregister_;

#ifdef BST_TEST
/* Test knobs, read by bst_loop_new. */
extern unsigned bst_test_uring_reject;   /* setup flags answered with -EINVAL (flag ladder) */
extern unsigned bst_test_uring_cq;       /* nonzero: IORING_SETUP_CQSIZE with this many */
extern unsigned bst_test_uring_nofeat;   /* BST_URF_* treated as missing */
extern int bst_test_uring_drain_ms;      /* >= 0: replaces BST_URING_DRAIN_MS */
extern unsigned bst_test_uring_sqe_fail; /* the next N SQE requests fail (SQ full) */
extern unsigned bst_test_uring_peer_fail; /* the next N getpeername calls fail */
extern unsigned bst_test_uring_splice_einval; /* SPLICE_IN submitted with a bad flag: -EINVAL */
extern unsigned bst_test_uring_pipes_max; /* nonzero: replaces BST_URING_PIPES_MAX */
/* Counters, loop thread only. */
extern unsigned bst_test_uring_overflows; /* waits that found IORING_SQ_CQ_OVERFLOW set */
extern unsigned bst_test_uring_rearms;    /* multishot recv/accept ended by the kernel, re-armed */
extern unsigned bst_test_uring_nobufs;    /* recv completions with -ENOBUFS */
extern unsigned bst_test_uring_accept_arms;
extern unsigned bst_test_uring_splices;   /* file -> pipe splices submitted */
extern unsigned bst_test_uring_splice_outs; /* pipe -> socket splices submitted */
extern unsigned bst_test_uring_pipes_made;
extern unsigned bst_test_uring_sendfiles;  /* sendfile fallbacks run */
extern unsigned bst_test_uring_copies;     /* recv buffers copied out of the ring */
extern unsigned bst_test_uring_zc;        /* SENDMSG_ZC submitted */
extern unsigned bst_test_uring_drained;   /* completions reaped by the last drain */
struct io_uring *bst_test_uring_ring(bst_loop *l);
unsigned bst_test_uring_dropped(bst_loop *l); /* CQEs the kernel dropped (koverflow) */
unsigned bst_test_uring_live(bst_loop *l);
unsigned bst_test_uring_pending_cancels(bst_loop *l);
#endif

#endif

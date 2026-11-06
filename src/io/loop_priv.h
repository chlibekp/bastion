/* Loop internals shared by loop.c, sock.c and the backends. Not for use outside src/io/. */
#ifndef BST_IO_LOOP_PRIV_H
#define BST_IO_LOOP_PRIV_H

#include "core/chain.h"
#include "core/slab.h"
#include "core/wheel.h"
#include "io/net.h"
#include "io/sock.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

#define BST_NOWAIT_DEVS 8u

/* Readiness slot of an internal user (recv, send). The poll slot is cb/ud/want/armed
 * below. The backend sees one registration per socket: the union of every armed slot. */
typedef struct bst_slot {
	uint32_t want;
	bool armed;
} bst_slot;

struct bst_ubuf;
struct bst_usend;
struct bst_upipe;

/* io_uring backend state of one socket (loop_uring.c, uring_net.c); epoll leaves it zero.
 * Every SQE that names the socket carries a tag in its user_data (the low 16 bits of gen
 * for polls, of recv_epoch for recv and accept, of s_tag for sends), so a completion of a
 * previous arm is told apart from the live one. */
typedef struct bst_usock {
	uint64_t prep_seq;  /* sequence number of the last SQE prepared for s */
	uint32_t epoch;     /* dispatch in which cnt was counted */
	uint16_t cnt;       /* recv or accept completions handled in that dispatch */
	bool deferred;      /* a completion of s was carried to the next dispatch */
	bool poll_live;     /* a POLL_ADD tagged poll_tag is in flight */
	uint16_t poll_tag;
	bool r_live;        /* the recv or accept tagged r_tag is in flight */
	bool r_mshot;       /* ... and it is multishot */
	bool r_acc;         /* ... and it is an accept */
	uint16_t r_tag;
	bool r_wait;        /* recv ended with -ENOBUFS: waiting for a buffer to come back */
	bool r_wlisted;     /* on the loop's buffer-wait list (holds an inflight) */
	bool r_pend;        /* on the loop's stash-delivery list (holds an inflight) */
	int st_end;         /* stashed end of stream: 1 EOF, < 0 error, 0 none */
	struct bst_ubuf *st_head, *st_tail; /* data received while the stream was stopped */
	bst_sock *wnext, *pnext;            /* buffer-wait and delivery lists */
	/* send */
	uint16_t s_tag;
	uint16_t s_out;     /* SQEs of the current send or connect in flight */
	uint16_t late;      /* of those, splices: they resolve their fds only when they run */
	uint8_t s_kinds;    /* bit per kind of those SQEs (for cancel at close) */
	bool s_pollout;     /* the socket was full: wait for POLLOUT before the next splice */
	bool s_zc;          /* the send in flight is zero-copy */
	int s_err;
	size_t pipe_fill;   /* file bytes in the pipe, not yet on the socket */
	size_t zc_hold;     /* bytes sent zero-copy whose buffers the kernel still uses */
	int fdup, fdup_src; /* our dup of the chain's file fd (-1 none), and the fd it dups */
	struct bst_usend *sctx;
	struct bst_upipe *pipe;
} bst_usock;

struct bst_sock {
	bst_loop *loop;
	int fd;
	/* poll slot (bst_io_poll) */
	bst_poll_cb cb;
	void *ud;
	uint32_t want;     /* events of the pending poll */
	uint32_t gen;      /* bumped by every bst_io_poll; async backends tag operations with it */
	uint32_t inflight; /* backend operations that still reference s after close */
	bool armed;      /* a poll is pending */
	bool registered; /* known to the backend */
	bool closed;     /* closed; waiting on the dead list, never dispatched */
	bool borrowed;   /* fd belongs to the caller (listener): never closed here */
	bool fd_held;    /* closed, but the backend still needs fd open: closed when s is freed */
	bst_sock *dnext; /* dead list */
	/* backend registration: union mask last programmed; kdisarmed when a one-shot event
	 * consumed it and it has not been re-armed yet */
	uint32_t kmask;
	bool kdisarmed;
	int last_err; /* last SO_ERROR seen (it is consumed when read) */
	/* recv slot: the recv stream, or accepting on a listener */
	bst_slot rslot;
	bst_recv_cb recv_cb;
	void *recv_ud;
	uint32_t recv_epoch; /* bumped by start/stop: a callback that changed it was superseded */
	bool recv_on;
	bst_accept_cb acc_cb;
	void *acc_ud;
	bool acc_on, acc_paused;
	bst_sock *lnext; /* loop's listener list */
	/* send slot: one send or connect */
	bst_slot wslot;
	bool send_on, is_connect;
	bst_chain *send_chain;
	bst_done_cb send_cb;
	void *send_ud;
	size_t send_bytes;
	int conn_err;   /* connect failed at once: reported from the next wakeup */
	bool ra_skip;   /* the next chunk was just read ahead: skip its probe */
	bool ra_busy;   /* readahead job or retry timer outstanding (holds an inflight) */
	bool in_ready;  /* inside bst_sock_ready_: backend sync is deferred to its end */
	struct {
		int fd;
		off_t off;
		size_t len;
	} ra;
	bst_timer ra_timer;
	bst_usock u;
};

/* Completion-based stream I/O (io_uring). The public functions in net_common.c check
 * arguments and set the socket's fields, then call these. NULL ops: net_common.c drives
 * the readiness slots itself. */
typedef struct bst_net_ops {
	int (*accept_start)(bst_sock *ls);
	int (*recv_start)(bst_sock *s);
	void (*recv_stop)(bst_sock *s);
	int (*send_start)(bst_sock *s); /* the chain may be empty: still completes from the loop */
	int (*connect)(bst_sock *s, const struct sockaddr_storage *to, socklen_t len);
	void (*send_kick)(bst_sock *s); /* a readahead job ended: continue the send */
} bst_net_ops;

/* What a backend provides. io_uring (Task 3) fills in the same table. */
typedef struct bst_loop_ops {
	bst_backend id;
	int (*open)(bst_loop *l, const bst_loop_cfg *cfg, bst_err *err); /* cfg may be NULL */
	void (*close)(bst_loop *l);
	/* Block up to timeout_ms (-1 forever). Returns the batch size (0 on EINTR or timeout)
	 * or -errno for a fatal error. The batch is held by the backend until dispatch. */
	int (*wait)(bst_loop *l, int timeout_ms);
	void (*dispatch)(bst_loop *l, int n);
	int (*poll_arm)(bst_sock *s, uint32_t events); /* poll(2) flags, one-shot */
	/* Forget s; the core closes the fd unless the backend set s->fd_held. Every operation
	 * that may still read caller memory for s (a send) is cancelled before it returns. */
	void (*sock_detach)(bst_sock *s);
	/* Async-signal-safe, any thread. Must never touch the backend's submission state
	 * (io_uring is SINGLE_ISSUER): only a write to a wake fd or similar. */
	void (*wake)(bst_loop *l);
	/* Optional. Called by bst_loop_free before close: cancel everything and reap
	 * completions until no operation is in flight, with a bounded wait. If some never
	 * complete, the backend leaks the memory they may use instead of freeing it. */
	void (*drain)(bst_loop *l);
	const bst_net_ops *net; /* NULL: readiness-driven stream I/O */
} bst_loop_ops;

extern const bst_loop_ops bst_loop_epoll_ops;
extern const bst_loop_ops bst_loop_uring_ops;

struct bst_loop {
	const bst_loop_ops *ops;
	void *be;
	bst_wheel wheel;
	bst_slab *socks;
	bst_sock *dead;
	atomic_bool stop;
	void (*wake_cb)(void *);
	void *wake_ud;
	struct bst_aio *aio;
	bst_slab *rbufs;    /* recv buffers (net_common.c) */
	bst_sock *listeners;
	size_t rbufs_out;                     /* recv buffers handed out and not yet released */
	dev_t nowait_dev[BST_NOWAIT_DEVS];    /* filesystems that refuse preadv2(RWF_NOWAIT) */
	unsigned nowait_n, nowait_next;
	uint32_t gen_seq; /* seeds gen and recv_epoch of each new socket (sock.c) */
};

uint64_t bst_mono_ms_(void);
/* Backend callbacks into the core, from dispatch. */
void bst_sock_ready_(bst_sock *s, uint32_t poll_events);
void bst_loop_woken_(bst_loop *l);
/* Backend: one in-flight operation that referenced s has completed (a cancel or its
 * -ECANCELED completion). A closed socket is freed at the end of the first iteration
 * in which its count is zero. The backend increments s->inflight when it submits one.
 * Epoll is synchronous and always reports zero; io_uring releases at the last completion
 * of each SQE (the one without IORING_CQE_F_MORE). */
void bst_sock_release_(bst_sock *s);
/* Extra hook run on the loop thread after a wake, after the aio drain (which is called
 * directly, not through this slot). For tests only: nothing in src/ sets it. */
/* Slot plumbing (sock.c). Arming makes the slot wait for events and programs the backend;
 * disarming reprograms only if the union changed. */
int bst_sock_slot_arm_(bst_sock *s, bst_slot *slot, uint32_t events);
void bst_sock_slot_disarm_(bst_sock *s, bst_slot *slot);
/* net_common.c: readiness for the recv and send slots, close hook, loop setup/teardown. */
void bst_net_recv_ready_(bst_sock *s, uint32_t events, int err);
void bst_net_send_ready_(bst_sock *s, uint32_t events, int err);
void bst_net_sock_close_(bst_sock *s);
/* The deferred backend sync failed at the end of an event: fail what was waiting. */
void bst_net_slot_failed_(bst_sock *s, bool recv, int err);
void bst_net_loop_free_(bst_loop *l);
/* Shared with the io_uring send path. bst_net_readahead_: true when the chunk is cold and
 * a pool job (or its retry timer) now owns the send; net->send_kick runs when it ends.
 * Consumes ra_skip. bst_net_send_finish_: end the send or connect, call done.
 * bst_net_send_err_: errno e of a failed write as the error to report (EPIPE after a
 * reset reports the reset). bst_net_peer_: sockaddr to bst_sockaddr, false if not IP. */
bool bst_net_readahead_(bst_sock *s, int fd, off_t off, size_t len);
void bst_net_send_finish_(bst_sock *s, int err);
int bst_net_send_err_(const bst_sock *s, int e);
size_t bst_net_send_budget_(void);
bool bst_net_peer_(const struct sockaddr_storage *ss, bst_sockaddr *out);
/* aio.c */
struct bst_aio;
struct bst_aio *bst_aio_new_(bst_loop *l, const bst_loop_cfg *cfg, bst_err *err);
void bst_aio_free_(struct bst_aio *a);
/* Loop thread: run the done callbacks of finished jobs. Called by bst_loop_woken_. */
void bst_aio_drain_(struct bst_aio *a);
void bst_loop_set_wake_cb(bst_loop *l, void (*cb)(void *), void *ud);

#endif

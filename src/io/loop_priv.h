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
#include <sys/types.h>

#define BST_NOWAIT_DEVS 8u

/* Readiness slot of an internal user (recv, send). The poll slot is cb/ud/want/armed
 * below. The backend sees one registration per socket: the union of every armed slot. */
typedef struct bst_slot {
	uint32_t want;
	bool armed;
} bst_slot;

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
};

/* What a backend provides. io_uring (Task 3) fills in the same table. */
typedef struct bst_loop_ops {
	bst_backend id;
	int (*open)(bst_loop *l, bst_err *err);
	void (*close)(bst_loop *l);
	/* Block up to timeout_ms (-1 forever). Returns the batch size (0 on EINTR or timeout)
	 * or -errno for a fatal error. The batch is held by the backend until dispatch. */
	int (*wait)(bst_loop *l, int timeout_ms);
	void (*dispatch)(bst_loop *l, int n);
	int (*poll_arm)(bst_sock *s, uint32_t events); /* poll(2) flags, one-shot */
	void (*sock_detach)(bst_sock *s);              /* forget s; the core closes the fd */
	/* Async-signal-safe, any thread. Must never touch the backend's submission state
	 * (io_uring is SINGLE_ISSUER): only a write to a wake fd or similar. */
	void (*wake)(bst_loop *l);
} bst_loop_ops;

extern const bst_loop_ops bst_loop_epoll_ops;

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
};

uint64_t bst_mono_ms_(void);
/* Backend callbacks into the core, from dispatch. */
void bst_sock_ready_(bst_sock *s, uint32_t poll_events);
void bst_loop_woken_(bst_loop *l);
/* Backend: one in-flight operation that referenced s has completed (a cancel or its
 * -ECANCELED completion). A closed socket is freed at the end of the first iteration
 * in which its count is zero. The backend increments s->inflight when it submits one.
 * Epoll is synchronous and always reports zero. */
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
/* aio.c */
struct bst_aio;
struct bst_aio *bst_aio_new_(bst_loop *l, const bst_loop_cfg *cfg, bst_err *err);
void bst_aio_free_(struct bst_aio *a);
/* Loop thread: run the done callbacks of finished jobs. Called by bst_loop_woken_. */
void bst_aio_drain_(struct bst_aio *a);
void bst_loop_set_wake_cb(bst_loop *l, void (*cb)(void *), void *ud);

#endif

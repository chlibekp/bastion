/* Loop internals shared by loop.c, sock.c and the backends. Not for use outside src/io/. */
#ifndef BST_IO_LOOP_PRIV_H
#define BST_IO_LOOP_PRIV_H

#include "core/slab.h"
#include "io/sock.h"

#include <stdatomic.h>
#include <stdbool.h>

struct bst_sock {
	bst_loop *loop;
	int fd;
	bst_poll_cb cb;
	void *ud;
	bool armed;      /* a poll is pending */
	bool registered; /* known to the backend */
	bool closed;     /* closed; waiting on the dead list, never dispatched */
	bst_sock *dnext; /* dead list */
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
	void (*wake)(bst_loop *l);                     /* async-signal-safe */
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
};

uint64_t bst_mono_ms_(void);
/* Backend callbacks into the core, from dispatch. */
void bst_sock_ready_(bst_sock *s, uint32_t poll_events);
void bst_loop_woken_(bst_loop *l);

#endif

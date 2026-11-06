/* Event loop: one per worker thread. Timers, wakeups and socket readiness behind a
 * backend-neutral API; nothing above src/io/ may use epoll_* or io_uring_* (architecture
 * section 3). Single-threaded except bst_loop_wake and bst_loop_stop. */
#ifndef BST_IO_LOOP_H
#define BST_IO_LOOP_H

#include "core/err.h"
#include "core/wheel.h"

#include <stddef.h>
#include <stdint.h>

typedef struct bst_loop bst_loop;
typedef enum { BST_BACKEND_AUTO, BST_BACKEND_URING, BST_BACKEND_EPOLL } bst_backend;

#define BST_URING_ENTRIES_DEFAULT 256u /* SQ entries; the CQ has twice as many */
#define BST_URING_ENTRIES_MAX 32768u
#define BST_URING_BUFS_DEFAULT 256u    /* provided recv buffers of BST_RECV_BUF_SIZE (net.h) */
#define BST_URING_BUFS_MAX 32768u

/* Later tasks add fields; zero-initialise and set what you need. The uring_* fields are
 * the io { } directives Task 4 registers; epoll ignores them. */
typedef struct bst_loop_cfg {
	bst_backend backend; /* AUTO currently resolves to epoll (Task 4 adds selection) */
	unsigned aio_threads; /* disk thread pool size, 0 = BST_AIO_THREADS_DEFAULT (aio.h); the
			       * aio_threads directive. Threads start in bst_loop_new. */
	unsigned aio_queue;   /* max jobs queued, running or awaiting done; 0 = default */
	unsigned uring_entries; /* SQ size, 0 = BST_URING_ENTRIES_DEFAULT; clamped to the max */
	unsigned uring_bufs;    /* recv buffers in the provided-buffer ring, 0 = default; rounded
				 * up to a power of two. One ring is shared by every socket of the
				 * loop: a caller holding buffers stalls recv until it unrefs them. */
	unsigned uring_sqpoll;  /* SQPOLL kernel thread idle time in ms; 0 = no SQPOLL */
	unsigned uring_napi;    /* NAPI busy-poll timeout in microseconds; 0 = off. Needs Linux 6.9;
				 * older kernels log a warning and run without it. */
	size_t uring_send_zc_min; /* memory sends of at least this many bytes use SENDMSG_ZC;
				   * 0 = never (the default until Phase 15 measures it) */
} bst_loop_cfg;

/* NULL on failure with err filled in. */
bst_loop *bst_loop_new(const bst_loop_cfg *cfg, bst_err *err);
/* Close every bst_sock first, and bst_buf_unref every buffer a recv callback received:
 * recv buffers come from a per-loop slab (epoll) or the loop's provided-buffer ring
 * (io_uring), neither thread-safe, so they must be released on the loop thread before this
 * call. A buffer still out aborts in BST_TEST builds and is logged at error level in
 * release builds. Pending timers are dropped without firing. Queued aio work still runs,
 * and its done callbacks run from here (aio.h).
 *
 * io_uring: operations of closed sockets may still be in flight (a close only queues
 * their cancellation). This call cancels everything still outstanding and reaps
 * completions until none is left, waiting at most one second (BST_URING_DRAIN_MS in
 * io/uring_priv.h); no callback runs meanwhile. If the kernel has not completed them by
 * then, an error is logged and the memory those operations may still use (recv buffers,
 * send state) is leaked, never freed under the kernel. Call it on the loop's thread: with io_uring, bst_loop_new, run
 * and free all belong to the thread that will run the loop (SINGLE_ISSUER). */
void bst_loop_free(bst_loop *l);

/* Runs until bst_loop_stop (returns 0, after the current batch finishes) or a fatal
 * backend error (returns a negative errno, reason logged). EINTR is retried. */
int bst_loop_run(bst_loop *l);
/* Thread-safe and async-signal-safe. Stop before run makes run return 0 at once, running
 * no batch. */
void bst_loop_stop(bst_loop *l);
bst_backend bst_loop_backend(const bst_loop *l);

/* Milliseconds from CLOCK_MONOTONIC (not the coarse clock), read fresh on each call. All
 * timer deadlines use this clock. */
uint64_t bst_loop_now_ms(const bst_loop *l);

/* Fire cb(ud) once, ms from now (minimum 1; never earlier, rounded up), on the loop thread.
 * The timer must have been through bst_timer_init and must stay valid until it fires or
 * is cancelled (bst_timer_cancel). Safe from any callback. */
void bst_loop_timer_arm(bst_loop *l, bst_timer *t, uint64_t ms, void (*cb)(void *), void *ud);

/* Thread-safe and async-signal-safe. Makes the loop wake and run its internal wake hook
 * on its thread. Wakes coalesce: many calls may produce one hook run, and a hook run can
 * be spurious (bst_loop_stop also wakes), so the hook must tolerate finding no work. A
 * wake before run is kept. */
void bst_loop_wake(bst_loop *l);

#endif

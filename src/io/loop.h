/* Event loop: one per worker thread. Timers, wakeups and socket readiness behind a
 * backend-neutral API; nothing above src/io/ may use epoll_* or io_uring_* (architecture
 * section 3). Single-threaded except bst_loop_wake and bst_loop_stop. */
#ifndef BST_IO_LOOP_H
#define BST_IO_LOOP_H

#include "core/err.h"
#include "core/wheel.h"

#include <stdint.h>

typedef struct bst_loop bst_loop;
typedef enum { BST_BACKEND_AUTO, BST_BACKEND_URING, BST_BACKEND_EPOLL } bst_backend;

/* Later tasks add fields; zero-initialise and set what you need. */
typedef struct bst_loop_cfg {
	bst_backend backend; /* AUTO currently resolves to epoll; URING fails until it is built */
	unsigned aio_threads; /* disk thread pool size, 0 = BST_AIO_THREADS_DEFAULT (aio.h); the
			       * aio_threads directive. Threads start in bst_loop_new. */
	unsigned aio_queue;   /* max jobs queued, running or awaiting done; 0 = default */
} bst_loop_cfg;

/* NULL on failure with err filled in. */
bst_loop *bst_loop_new(const bst_loop_cfg *cfg, bst_err *err);
/* Close every bst_sock first. Pending timers are dropped without firing. */
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

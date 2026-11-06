/* A worker: one process, one loop, one slot of every listener. */
#ifndef BST_PROC_WORKER_H
#define BST_PROC_WORKER_H

#include "core/addr.h"
#include "io/loop.h"
#include "proc/runtime.h"

#include <stdbool.h>

#define BST_ACCEPT_RETRY_MS 1000u  /* a paused listener (EMFILE) tries again after this; Task 9 */
#define BST_ACCEPT_SWEEP_MS 5u      /* first sweep of the listeners on io_uring; doubles each time */
#define BST_ACCEPT_SWEEP_MAX_MS 1000u
#define BST_ACCEPT_DRAIN_MAX 4096u /* queued connections a stopping worker still takes, per listener */

typedef struct bst_worker bst_worker;

/* The protocol's entry point, set by the HTTP phases: called on the loop thread for each
 * accepted connection, which it owns (fd is non-blocking and close-on-exec). peer is NULL for a
 * non-IP peer. A connection that must hold up a graceful stop is bracketed with
 * bst_worker_conn_opened and bst_worker_conn_closed. With no hook the connection is closed. */
typedef void (*bst_worker_conn_fn)(bst_worker *w, int fd, const bst_sockaddr *peer,
				   const bst_cfg_listen *l);
extern bst_worker_conn_fn bst_worker_on_conn;

bst_loop *bst_worker_loop(bst_worker *w);
void bst_worker_conn_opened(bst_worker *w);
/* In a stopping worker the last close ends the process, once the loop gets control back. */
void bst_worker_conn_closed(bst_worker *w);

/* The CPU slot belongs on, or -1 to leave it unpinned. Today the only reason to pin is `steering
 * incoming_cpu`, which assumes slot i runs on CPU i % ncpu; Phase 14's worker_cpu_affinity
 * extends this function, the one place that decides. */
int bst_worker_cpu(int slot, bool pin, int ncpu);

/* Runs a worker in a forked child. Never returns. */
void bst_worker_main(int slot, bst_runtime *rt) __attribute__((noreturn));

#endif

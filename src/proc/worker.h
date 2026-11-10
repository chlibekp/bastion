/* A worker: one process, one loop, one slot of every listener. */
#ifndef BST_PROC_WORKER_H
#define BST_PROC_WORKER_H

#include "core/addr.h"
#include "io/loop.h"
#include "proc/runtime.h"

#include <stdbool.h>
#include <stddef.h>

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
const bst_config *bst_worker_config(const bst_worker *w);
/* Called once when a graceful stop has closed the listeners: the protocol closes its idle
 * connections and ends the others after the response in flight. */
extern void (*bst_worker_on_drain)(bst_worker *w);
void bst_worker_conn_opened(bst_worker *w);
/* In a stopping worker the last close ends the process, once the loop gets control back. */
void bst_worker_conn_closed(bst_worker *w);

/* ---- overload protection (io/admission.h; the figures are the limits { } block) ---- */

const bst_cfg_limits *bst_worker_limits(const bst_worker *w);
/* The accept path asks this itself: false means the connection is already counted and the fd is
 * the caller's to close. A protocol that takes connections some other way asks it too. */
bool bst_admit_conn(bst_worker *w);
/* Memory budget for request state: false charges nothing and means refuse the request with
 * limits.overload_status and Retry-After (bst_worker_refused counts it). Any thread. */
bool bst_worker_mem_charge(bst_worker *w, size_t n);
void bst_worker_mem_release(bst_worker *w, size_t n);
bool bst_overloaded(const bst_worker *w); /* the budget is spent: refuse new requests */
void bst_worker_refused(bst_worker *w);

/* The CPU slot belongs on, or -1 to leave it unpinned. Today the only reason to pin is `steering
 * incoming_cpu`, which assumes slot i runs on CPU i % ncpu; Phase 14's worker_cpu_affinity
 * extends this function, the one place that decides. */
int bst_worker_cpu(int slot, bool pin, int ncpu);

/* Runs a worker in a forked child. Never returns. */
void bst_worker_main(int slot, bst_runtime *rt) __attribute__((noreturn));

#endif

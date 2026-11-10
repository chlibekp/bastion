/* Overload protection for one worker (architecture section 4): how many connections it holds,
 * how much memory request state may take, and what to do when the process runs out of
 * descriptors. The figures come from the limits { } block; nothing here is a tunable of its
 * own.
 *
 * Threads. The counters are atomic, so the memory budget can be charged and released from an
 * aio pool thread too. Everything else, and every call that counts an event (it arms the
 * report timer), belongs to the loop thread. */
#ifndef BST_IO_ADMISSION_H
#define BST_IO_ADMISSION_H

#include "config/compile.h"
#include "core/wheel.h"
#include "io/loop.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

#define BST_ADM_REPORT_MS 1000u /* events are logged in one line per this long, never per event */
#define BST_ADM_SHED_MAX 4096u  /* connections one descriptor-limit shed accepts and closes */

typedef struct bst_admission {
	const bst_cfg_limits *lim;
	bst_loop *loop;
	int dup_src; /* what the reserve is a duplicate of */
	atomic_size_t mem_used;
	atomic_ullong closed;    /* connections closed over max_connections */
	atomic_ullong refused;   /* requests answered with overload_status */
	atomic_ullong fd_closed; /* connections accepted and closed at the descriptor limit */
	bst_timer report;
	bool report_armed;
	int reserve[BST_LIMITS_RESERVE_FDS_MAX]; /* the first lim->reserve_fds are used; -1: not held */
} bst_admission;

/* Holds lim->reserve_fds descriptors, duplicates of dup_src (any open descriptor that is
 * never closed: it is only a way to take a slot without opening a file, which a sandbox forbids;
 * a worker passes its stdin, /dev/null). A shortfall is
 * logged: the worker then has fewer to give up. lim must outlive adm. */
void bst_adm_init(bst_admission *adm, const bst_cfg_limits *lim, bst_loop *loop, int dup_src);

/* True when a worker holding `conns` connections may take one more. Otherwise counts a
 * closed connection and returns false: the caller closes the fd. */
bool bst_adm_admit(bst_admission *adm, unsigned long long conns);

/* Memory budget. charge adds n and returns true, or returns false and charges nothing when
 * that would pass worker_memory. release gives back what charge took. Any thread. */
bool bst_adm_mem_charge(bst_admission *adm, size_t n);
void bst_adm_mem_release(bst_admission *adm, size_t n);
/* True once the budget is spent: a new request is answered with overload_status. */
bool bst_adm_overloaded(const bst_admission *adm);
/* Counts a request answered with overload_status. */
void bst_adm_refused(bst_admission *adm);

/* At EMFILE or ENFILE: gives up the reserved descriptors, accepts the connections queued on
 * listen_fd and closes each at once, takes the reserve back. Returns how many it closed. */
unsigned bst_adm_shed_fds(bst_admission *adm, int listen_fd);

#endif

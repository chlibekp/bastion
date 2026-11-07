/* Master's private state and the startup steps split out of master.c (master_setup.c). */
#ifndef BST_PROC_MASTER_PRIV_H
#define BST_PROC_MASTER_PRIV_H

#include "core/counters.h"
#include "core/err.h"
#include "proc/master.h"
#include "proc/runtime.h"

#include <poll.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum { RUNNING, STOP_GRACEFUL, STOP_FAST } master_state;

typedef struct child {
	pid_t pid;           /* 0: none */
	int chan;            /* master's end, -1 when closed */
	int slot;            /* -1: the helper */
	bool ready;          /* READY received from this process */
	bool replacing;      /* told to drain for a backend change: not a crash */
	unsigned crashes;    /* in a row */
	uint64_t started_ms;
	uint64_t respawn_at; /* 0: nothing scheduled */
	uint64_t eof_at;     /* its channel closed at this time, 0: open */
	uint64_t kill_at;    /* a replacement's deadline, 0: none */
} child;

typedef struct master {
	bst_runtime rt;
	master_state state;
	child *kids; /* workers by slot, then the helper */
	int nkids;
	struct pollfd *pfds;
	int *poll_kid; /* the child behind each pfds entry */
	int sigfd;
	int pid_fd;
	int stats_fd;
	size_t stats_size;
	bool started;     /* every child has been ready, or the startup deadline passed */
	bool announced;   /* the `ready:` line went out */
	uint64_t startup_deadline; /* 0 once started */
	bool failed;      /* startup failed: exit 1 */
	bool helper_told; /* graceful stop reached the helper */
	uint64_t deadline; /* stop deadline, 0: none */
	bst_counter_id crash_ctr;
} master;

/* Startup steps, run once in this order before any fork. 0, or -1 with *e set. */
int bst_master_resolve_user_(master *m, bst_err *e);
int bst_master_open_pid_file_(master *m, bst_err *e);
int bst_master_probe_backend_(master *m, bst_err *e);
int bst_master_decide_sqpoll_(master *m, bst_err *e);
int bst_master_create_listeners_(master *m, bst_err *e);
int bst_master_map_status_(master *m, bst_err *e);

#endif

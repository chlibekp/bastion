/* What master hands to every child across fork: the compiled config, the listening sockets, the
 * decisions taken once at start, shared memory, and the child's end of its channel. */
#ifndef BST_PROC_RUNTIME_H
#define BST_PROC_RUNTIME_H

#include "config/compile.h"
#include "io/loop.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* Exit status of a child that can not start at all: master ends a startup on it, where any
 * other death is a crash to retry. A respawn that exits this way, on a server already running,
 * counts as a crash: the other workers are serving and a crash loop backs off. */
#define BST_EXIT_STARTUP 78

typedef struct bst_rt_listener {
	const bst_cfg_listen *cfg;
	int *fds; /* one per worker slot; a worker closes all but its own */
} bst_rt_listener;

/* Written by one worker, read by master only to word a log line, so a lie costs nothing. */
typedef struct bst_slot_stats {
	_Alignas(64) atomic_ullong conns;
} bst_slot_stats;

typedef struct bst_runtime {
	bst_config *cfg;
	int nworkers;
	bst_rt_listener *listeners;
	size_t nlisteners;

	/* Computed once in master, before any pinning: aio_threads auto needs the whole machine. */
	bst_loop_cfg loop_cfg;
	bool backend_auto;     /* the config said auto */
	bst_backend backend;   /* what every worker must run on: master's probe, or the fallback */
	char epoll_reason[192];

	bool pin_workers; /* a listener uses steering incoming_cpu */
	int ncpu;         /* bst_listener_ncpu: slot i belongs on CPU i % ncpu */

	bool drop_uid, drop_gid;
	uid_t uid;
	gid_t gid;

	pid_t master_pid;
	int log_base_fd;  /* the error log or stderr; each process reopens it for itself */
	int log_level;
	int log_inherited; /* master's own description, closed by a child that made its own */

	bst_slot_stats *stats; /* nworkers entries, in the shared `status` region */

	int channel; /* this child's end of its channel */
} bst_runtime;

/* ---- logsink.c ---- */

/* The fd of the configured destination: path opened for append (created 0640), or stderr when
 * path is NULL. -1 with err set. */
int bst_logsink_open(const char *path, bst_err *err);
/* Points this process's logger at a description of its own and returns it: master and every
 * child call this, so a pipe's O_NONBLOCK never reaches the process that gave us the pipe.
 *
 *   pipe, tty, other device   reopened through /proc/self/fd with O_NONBLOCK: a new description
 *                             of the same file. A full pipe drops lines, it never blocks.
 *   regular file              reopened with O_APPEND (a shell's `2> file` has no O_APPEND, and
 *                             separate descriptions would overwrite each other).
 *   socket                    cannot be reopened: a dup, with bst_log_set_socket, so each write
 *                             is send(MSG_DONTWAIT) and O_NONBLOCK stays off the shared socket.
 *
 * Returns the fd, or -1 when none could be had (no /proc, or a pipe this user may not open).
 * The logger is then pointed at nothing and drops every line, counted, because the choice
 * left would be a blocking write on the event loop. */
int bst_logsink_attach(int base_fd, int level);

/* ---- child.c: what a worker and the helper share ---- */

/* First thing in a child: signals, name, log tag, its own log description, crash handler,
 * SIGPIPE, and closing the listeners that are not its own. slot < 0 is the helper. */
void bst_child_start(bst_runtime *rt, int slot, const char *tag);
/* Creates this child's loop. Under backend auto an io_uring failure falls back to epoll, with
 * the reason logged; with backend uring it exits BST_EXIT_STARTUP. Call on the thread that will
 * run the loop, and before bst_child_drop: SINGLE_ISSUER binds the ring at enable, and
 * kernel.io_uring_disabled=1 lets only root create one. */
bst_loop *bst_child_loop(bst_runtime *rt, int slot, const char *tag);
/* setgroups, setgid, setuid. Any failure exits BST_EXIT_STARTUP: never run on as root. */
void bst_child_drop(const bst_runtime *rt);
/* PR_SET_PDEATHSIG, after the drop because changing user clears it, then the getppid recheck for
 * a master that died before the prctl. */
void bst_child_watch_master(const bst_runtime *rt);

#endif

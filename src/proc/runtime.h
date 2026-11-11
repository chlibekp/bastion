/* What master hands to every child across fork: the compiled config, the listening sockets, the
 * decisions taken once at start, shared memory, and the child's end of its channel. */
#ifndef BST_PROC_RUNTIME_H
#define BST_PROC_RUNTIME_H

#include "config/compile.h"
#include "io/loop.h"
#include "proc/sandbox.h"

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

	/* uring_sqpoll with anything to drop: see bst_child_loop_and_drop */
	bool ring_after_drop;

	bool pin_workers; /* a listener uses steering incoming_cpu */
	int ncpu;         /* bst_listener_ncpu: slot i belongs on CPU i % ncpu */

	bool drop_uid, drop_gid;
	uid_t uid;
	gid_t gid;

	bool use_ns;  /* `namespaces on`, and master found them permitted */
	int pidns_fd; /* master's own PID namespace, to come back to after each fork; master only */

	pid_t master_pid;
	int log_base_fd;  /* the error log or stderr; each process reopens it for itself */
	int log_level;
	int log_inherited; /* master's own description, closed by a child that made its own */

	bst_slot_stats *stats; /* nworkers entries, in the shared `status` region */
	void *ocsp;	       /* the shared OCSP staples (tls/ocsp.h), NULL without stapling */
	void *tickets;	       /* the shared session ticket keys (tls/tickets.h), NULL without tickets */

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
 *   pipe it may not reopen    (a gosu entrypoint, a root-owned pipe to a service) written through
 *                             a private pipe and splice(SPLICE_F_NONBLOCK) into a dup: that
 *                             needs neither a reopen nor O_NONBLOCK on the shared description.
 *                             A full pipe drops lines here too, and holds fewer: each line
 *                             takes one of the pipe's slots (16 by default).
 *   regular file              reopened with O_APPEND (a shell's `2> file` has no O_APPEND, and
 *                             separate descriptions would overwrite each other).
 *   socket                    cannot be reopened: a dup, with bst_log_set_socket, so each write
 *                             is send(MSG_DONTWAIT) and O_NONBLOCK stays off the shared socket.
 *
 * Returns the fd, or -1 when none could be had: a tty this user may not open (a root-owned pty
 * under a gosu entrypoint), or any non-pipe with no /proc. splice into a tty can block, so the
 * logger is pointed at nothing and drops every line, crash reports too, counted, because the
 * choice left would be a blocking write on the event loop. Master says so on stderr at start. */
int bst_logsink_attach(int base_fd, int level);

/* ---- child.c: what a worker and the helper share ---- */

/* First thing in a child: signals, name, log tag, its own log description, crash handler,
 * SIGPIPE, and closing the listeners that are not its own. slot < 0 is the helper. */
void bst_child_start(bst_runtime *rt, int slot, const char *tag);
/* Creates this child's loop. Under backend auto an io_uring failure falls back to epoll, with
 * the reason logged; with backend uring it exits BST_EXIT_STARTUP. */
bst_loop *bst_child_loop(bst_runtime *rt, int slot, const char *tag);
/* The loop and the privilege drop, in the only safe order, on the thread that will run the loop
 * (SINGLE_ISSUER binds the ring at enable).
 *
 * A plain ring comes first: kernel.io_uring_disabled=1 lets only root create one, and its
 * requests run with the credentials of the task submitting them, so it does not stay root.
 *
 * An SQPOLL ring comes after the drop. Its kernel thread keeps the credentials of the ring's
 * creator and runs whatever the worker writes to the SQ ring, so a ring made as root would run
 * every request as full root for the life of the worker. Ring restrictions do not fix that (they
 * leave CONNECT open), and neither does IORING_REGISTER_PERSONALITY, since the worker writes the
 * SQEs and can use personality 0. The same goes for capabilities when no `user` changes the uid.
 * Master decides with bst_child_probe_ring_as_user.
 *
 * Between the two sits step 2 of the sandbox: namespaces want root and the drop ends that. */
bst_loop *bst_child_loop_and_drop(bst_runtime *rt, int slot, const char *tag);
/* From master, before any worker: can the `user` create this ring after the drop? Forks a child
 * that drops and tries. 0, or -1 with the reason in why. */
int bst_child_probe_ring_as_user(const bst_runtime *rt, char *why, size_t cap);
/* setgroups, setgid, setuid, then every capability of every thread. Any failure exits
 * BST_EXIT_STARTUP: never run on as root. */
void bst_child_drop(const bst_runtime *rt);
/* PR_SET_PDEATHSIG, after the drop because changing user clears it, then a recheck for a master
 * that died before the prctl: getppid, or in a PID namespace, where getppid is 0 either way, EOF
 * on the channel. */
void bst_child_watch_master(const bst_runtime *rt);
/* Steps 4 to 6 of the sandbox. Exits BST_EXIT_STARTUP on failure. */
void bst_child_sandbox(const bst_runtime *rt, bst_sandbox_role role);

/* ---- namespaces.c ---- */

/* In master, once: can it make the namespaces `namespaces on` asks for? Sets rt->use_ns. Refused,
 * it warns, or under `require` returns -1 with e set. */
int bst_ns_setup(bst_runtime *rt, bst_err *e);
/* fork, the child in a PID namespace of its own when rt->use_ns. As fork. */
pid_t bst_ns_fork(const bst_runtime *rt);
/* In the child, as root: mount, IPC and UTS namespaces and a private root. 0, or -1 with e set
 * under `require`: refused without it, this warns. */
int bst_ns_enter(const bst_runtime *rt, const bst_sandbox_paths *p, bst_err *e);

#endif

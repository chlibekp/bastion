/* Listening sockets and their TCP options (architecture section 4).
 *
 * Master creates one socket per worker slot for each distinct listen address, all with
 * SO_REUSEPORT, applies the listener's tcp_profile and hands the fds to workers, which
 * inherit them through fork (no exec, so SOCK_CLOEXEC does not get in the way). The kernel
 * spreads new connections over the slots by source address and port. Because master keeps
 * its own copy of every fd, replacing a worker never loses queued connections.
 *
 * Options. Every option the profile asks for is applied by one table-driven function
 * (sockopts.c). A kernel that refuses one gives a warning through the logger naming the
 * option and the errno, once per listener, and startup goes on; with `require` it is a
 * startup error. Some options can succeed and still do nothing (a buffer clamped by
 * net.core.rmem_max, TCP Fast Open without the net.ipv4.tcp_fastopen server bit, a backlog
 * above net.core.somaxconn): those are checked and reported the same way, never silently.
 *
 * Accepted connections inherit nearly every option from the listener (the kernel copies
 * them), so bst_sock_apply_accepted touches only what is not inherited (TCP_QUICKACK) and
 * skips values the kernel already has: with the default profile it makes no syscall. */
#ifndef BST_IO_LISTENER_H
#define BST_IO_LISTENER_H

#include "config/compile.h"
#include "core/err.h"
#include "io/tcp_profile.h"

#define BST_LISTENER_MAX_SLOTS 8192 /* two generations of the largest worker count */

/* Creates `slots` listening sockets for l, in fds[0..slots-1]: SO_REUSEPORT, SOCK_NONBLOCK,
 * SOCK_CLOEXEC, IPV6_V6ONLY on an IPv6 address (so `listen 80` and `listen [::]:80` coexist),
 * bound, listening, with l->tcp (or the documented default profile when NULL) applied. With
 * steering incoming_cpu, slot i prefers CPU i modulo the online CPUs: it assumes worker i
 * runs on that CPU.
 * 0 on success. -1 with err set otherwise (the address and errno for a failed bind, the
 * option for a refused `require`): every socket already created is closed and fds[] is all
 * -1. err has no file or line: it is a startup error, not a config error. */
int bst_listener_create(const bst_cfg_listen *l, int slots, int *fds, bst_err *err);

/* The distinct listen addresses of a config, first occurrence of each, in config order: the
 * set master creates sockets for (servers that differ only by name share a socket). *out is
 * malloc'd, to free(); entries point into cfg. 0, or -1 with err set. */
int bst_config_listeners(const bst_config *cfg, const bst_cfg_listen ***out, size_t *n,
			 bst_err *err);

/* Applies the options a socket does not inherit from its listener to one accepted fd.
 * Returns 0, or the negative errno of the first option the kernel refused (the fd stays
 * open: the connection is still good). Each refused option is logged once per process.
 * NULL profile or nothing to do is 0 and no syscall. On the accept path: keep it cheap. */
int bst_sock_apply_accepted(int fd, const bst_tcp_profile *p);

/* ---- listener.c to sockopts.c ---- */

typedef struct bst_sockopt_target {
	int fd;
	int family;          /* AF_INET or AF_INET6 */
	int slot, ncpu;      /* steering: slot i prefers CPU i % ncpu */
	const char *addr;    /* "1.2.3.4:80" or "[::]:80", for messages */
} bst_sockopt_target;

typedef enum bst_sockopt_stage {
	BST_SO_BEFORE_BIND, /* the socket is new */
	BST_SO_LISTENING,   /* after listen(2): Fast Open and the backlog check */
} bst_sockopt_stage;

/* Applies the options of p that belong to `stage`. A refusal without `require` is logged
 * as a warning the first time (bit per option in *reported, kept by the caller across the
 * slots of one listener) and skipped. A refusal with `require` is -1 and err set. */
int bst_sockopts_apply_(const bst_sockopt_target *t, const bst_tcp_profile *p,
			bst_sockopt_stage stage, uint32_t *reported, bst_err *err);

#ifdef BST_TEST
/* setsockopt(2) calls the option table made (every call, any stage), so a test can prove the
 * accept path stays cheap. Single-threaded tests only. */
extern unsigned bst_test_sockopt_calls;
/* If > 0, the CPU count steering uses instead of the online CPUs (to test slots > CPUs). */
extern int bst_test_ncpu;
/* `bastion --test-listeners N [--test-accept-ms MS]`: creates the config's listeners with N
 * slots, prints the options each socket reads back with getsockopt as a JSON line, accepts
 * for MS milliseconds if asked and prints what each slot accepted. Compiled into test builds
 * only. Returns the exit status. */
int bst_test_listeners_main(const bst_config *cfg, int slots, unsigned accept_ms);
#endif

#endif

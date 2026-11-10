/* See runtime.h. */
#include "proc/runtime.h"

#include "core/log.h"
#include "io/net.h"
#include "proc/sandbox.h"
#include "proc/signals.h"
#include "proc/test_hooks.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* The log has its own description by now, so 0, 1 and 2 can let go of whatever they were: a tty
 * above all. Sanitizers write to fd 2, so a report from a child needs log_path to be seen. */
static void stdio_to_null(void)
{
	int null = open("/dev/null", O_RDWR | O_NOCTTY);
	if (null < 0) {
		bst_log(BST_LOG_ERROR, "/dev/null: %s", strerror(errno));
		_exit(BST_EXIT_STARTUP);
	}
	for (int fd = 0; fd < 3; fd++)
		if (fd != null)
			dup2(null, fd);
	if (null > 2)
		close(null);
}

void bst_child_start(bst_runtime *rt, int slot, const char *tag)
{
	bst_signals_child();
	bst_io_ignore_sigpipe();
	char comm[16];
	snprintf(comm, sizeof comm, "bst:%s", tag);
	prctl(PR_SET_NAME, comm);
	bst_log_set_tag(tag);
	/* A new session has no controlling tty: a compromised worker must not be able to type into
	 * root's shell with TIOCSTI. Before the drop, like everything here. */
	if (setsid() < 0)
		bst_log(BST_LOG_WARN, "setsid: %s", strerror(errno));
	bst_logsink_attach(rt->log_base_fd, rt->log_level);
	if (rt->log_inherited >= 0)
		close(rt->log_inherited);
	rt->log_inherited = -1;
	if (rt->log_base_fd > 2)
		close(rt->log_base_fd);
	stdio_to_null();
	bst_crash_install();
	bst_sandbox_sanitizer_prepare(tag);
	for (size_t i = 0; i < rt->nlisteners; i++)
		for (int s = 0; s < rt->nworkers; s++)
			if (s != slot && rt->listeners[i].fds[s] >= 0) {
				close(rt->listeners[i].fds[s]);
				rt->listeners[i].fds[s] = -1;
			}
}

bst_loop *bst_child_loop(bst_runtime *rt, int slot, const char *tag)
{
	bst_loop_cfg lc = rt->loop_cfg;
	bst_err e = {.msg = ""};
#ifdef BST_TEST
	bst_test_child_loop(slot);
#else
	(void)slot;
#endif
	bst_sandbox_restrict_rings();
	bst_loop *l = bst_loop_new(&lc, &e);
	char why[256];
	if (l == NULL && rt->backend_auto && lc.backend != BST_BACKEND_EPOLL) {
		snprintf(why, sizeof why, "%s: %s", tag, e.msg);
		bst_log(BST_LOG_WARN, "%s fell back to epoll: %s", tag, e.msg);
		lc.backend = BST_BACKEND_EPOLL;
		lc.epoll_reason = why;
		l = bst_loop_new(&lc, &e);
	} else if (l != NULL && lc.backend == BST_BACKEND_AUTO &&
		   bst_loop_backend(l) == BST_BACKEND_EPOLL) {
		bst_log(BST_LOG_WARN, "%s fell back to epoll: %s", tag, bst_loop_backend_reason(l));
	}
	if (l == NULL) {
		bst_log(BST_LOG_ERROR, "%s: no event loop: %s", tag, e.msg);
		_exit(BST_EXIT_STARTUP);
	}
	return l;
}

#ifdef BST_TEST
#define FAIL(step) bst_test_drop_fails(step)
#else
#define FAIL(step) false
#endif

static void drop_failed(const char *what)
{
	bst_log(BST_LOG_ERROR, "%s failed: %s", what, strerror(errno));
	_exit(BST_EXIT_STARTUP);
}

static void sandbox_failed(const bst_err *e)
{
	bst_log(BST_LOG_ERROR, "sandbox: %s", e->msg);
	_exit(BST_EXIT_STARTUP);
}

void bst_child_drop(const bst_runtime *rt)
{
	const bst_cfg_sandbox *sb = &rt->cfg->global.sandbox;
	bst_err e = {.msg = ""};
	if (sb->drop_caps && rt->drop_uid && bst_sandbox_keep_caps(&e) != 0)
		sandbox_failed(&e);
	if (rt->drop_gid) {
		if (setgroups(1, &rt->gid) != 0 || FAIL("setgroups"))
			drop_failed("setgroups");
		if (setgid(rt->gid) != 0 || FAIL("setgid"))
			drop_failed("setgid");
	}
	if (rt->drop_uid) {
		if (setuid(rt->uid) != 0 || FAIL("setuid"))
			drop_failed("setuid");
		if (rt->uid != 0 && (setuid(0) == 0 || FAIL("regain"))) { /* it must not be undoable */
			errno = EPERM;
			drop_failed("dropping privileges for good");
		}
	}
	if (sb->drop_caps && bst_sandbox_drop_caps(sb, &e) != 0)
		sandbox_failed(&e);
#ifdef BST_TEST
	bst_test_child_dropped();
#endif
}

static bst_sandbox_paths child_paths(const bst_runtime *rt)
{
	const bst_cfg_sandbox *sb = &rt->cfg->global.sandbox;
	return (bst_sandbox_paths){ .read = sb->extra_read, .nread = sb->nextra_read,
				    .write = sb->extra_write, .nwrite = sb->nextra_write };
}

static void enter_namespaces(const bst_runtime *rt)
{
	bst_sandbox_paths p = child_paths(rt);
	bst_err e = {.msg = ""};
	if (bst_ns_enter(rt, &p, &e) != 0)
		sandbox_failed(&e);
}

void bst_child_sandbox(const bst_runtime *rt, bst_sandbox_role role)
{
	bst_sandbox_paths p = child_paths(rt);
	bst_err e = {.msg = ""};
	if (bst_sandbox_apply(&rt->cfg->global.sandbox, role, &p, &e) != 0)
		sandbox_failed(&e);
}

bst_loop *bst_child_loop_and_drop(bst_runtime *rt, int slot, const char *tag)
{
	if (rt->ring_after_drop) {
		enter_namespaces(rt);
		bst_child_drop(rt);
		bst_loop *l = bst_child_loop(rt, slot, tag);
		bst_sandbox_set_loop(l);
		return l;
	}
	bst_loop *l = bst_child_loop(rt, slot, tag);
	bst_sandbox_set_loop(l);
	enter_namespaces(rt);
	bst_child_drop(rt);
	return l;
}

int bst_child_probe_ring_as_user(const bst_runtime *rt, char *why, size_t cap)
{
	int p[2];
	why[0] = '\0';
	if (pipe2(p, O_CLOEXEC) != 0) {
		snprintf(why, cap, "pipe: %s", strerror(errno));
		return -1;
	}
	pid_t pid = fork();
	if (pid < 0) {
		snprintf(why, cap, "fork: %s", strerror(errno));
		close(p[0]);
		close(p[1]);
		return -1;
	}
	if (pid == 0) {
		close(p[0]);
		bst_child_drop(rt);
		bst_loop_cfg lc = rt->loop_cfg;
		lc.backend = BST_BACKEND_URING;
		lc.aio_threads = 1;
		bst_err e = {.msg = ""};
		bst_sandbox_restrict_rings(); /* the ring a worker will really have */
		if (bst_loop_new(&lc, &e) != NULL)
			_exit(0); /* the kernel takes the ring back */
		(void)!write(p[1], e.msg, strlen(e.msg));
		_exit(1);
	}
	close(p[1]);
	ssize_t n = read(p[0], why, cap - 1);
	why[n > 0 ? (size_t)n : 0] = '\0';
	close(p[0]);
	int st = 0;
	while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
		;
	return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : -1;
}

/* In a PID namespace getppid is 0 with master alive or dead, and its end of the channel is the
 * one thing that tells: a child holds only its own end, so EOF means master has gone. */
static bool master_gone(const bst_runtime *rt)
{
	pid_t parent = getppid();
	if (parent != 0)
		return parent != rt->master_pid;
	char c;
	return recv(rt->channel, &c, sizeof c, MSG_PEEK | MSG_DONTWAIT) == 0;
}

void bst_child_watch_master(const bst_runtime *rt)
{
	bool arm = true;
#ifdef BST_TEST
	arm = bst_test_child_watch();
#endif
	/* SIGKILL: the handler-free death, the same in every sandbox state. Workers ignore the
	 * polite signals, because those belong to master. */
	if (arm && prctl(PR_SET_PDEATHSIG, SIGKILL) != 0)
		bst_log(BST_LOG_WARN, "PR_SET_PDEATHSIG: %s", strerror(errno));
	if (master_gone(rt)) {
		bst_log(BST_LOG_WARN, "master is gone: exiting");
		_exit(0);
	}
}

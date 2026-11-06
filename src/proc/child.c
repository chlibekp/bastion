/* See runtime.h. */
#include "proc/runtime.h"

#include "core/log.h"
#include "io/net.h"
#include "proc/signals.h"
#include "proc/test_hooks.h"

#include <errno.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

void bst_child_start(bst_runtime *rt, int slot, const char *tag)
{
	bst_signals_child();
	bst_io_ignore_sigpipe();
	char comm[16];
	snprintf(comm, sizeof comm, "bst:%s", tag);
	prctl(PR_SET_NAME, comm);
	bst_log_set_tag(tag);
	bst_logsink_attach(rt->log_base_fd, rt->log_level);
	if (rt->log_inherited >= 0)
		close(rt->log_inherited);
	rt->log_inherited = -1;
	if (rt->log_base_fd > 2)
		close(rt->log_base_fd);
	bst_crash_install();
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

static void drop_failed(const char *what)
{
	bst_log(BST_LOG_ERROR, "%s failed: %s", what, strerror(errno));
	_exit(BST_EXIT_STARTUP);
}

void bst_child_drop(const bst_runtime *rt)
{
	if (rt->drop_gid) {
		if (setgroups(1, &rt->gid) != 0)
			drop_failed("setgroups");
		if (setgid(rt->gid) != 0)
			drop_failed("setgid");
	}
	if (rt->drop_uid) {
		if (setuid(rt->uid) != 0)
			drop_failed("setuid");
		if (rt->uid != 0 && setuid(0) == 0) { /* the drop must not be undoable */
			errno = EPERM;
			drop_failed("dropping privileges for good");
		}
	}
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
	if (getppid() != rt->master_pid) {
		bst_log(BST_LOG_WARN, "master is gone: exiting");
		_exit(0);
	}
}

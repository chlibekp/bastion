/* Master startup, step by step: everything decided once, before any fork. See master.c. */
#include "proc/master_priv.h"

#include "core/counters.h"
#include "core/log.h"
#include "core/shm.h"
#include "io/backend.h"
#include "io/listener.h"
#include "io/net.h"
#include "proc/channel.h"
#include "proc/helper.h"
#include "proc/runtime.h"
#include "proc/signals.h"
#include "proc/test_hooks.h"
#include "proc/worker.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---- start: everything decided once, before any fork ---- */

int bst_master_resolve_user_(master *m, bst_err *e)
{
	bst_runtime *rt = &m->rt;
	const bst_cfg_global *g = &rt->cfg->global;
	if (geteuid() != 0) {
		if (g->user != NULL || g->group != NULL)
			bst_log(BST_LOG_WARN, "user and group need root: ignored, workers run as uid %ld",
				(long)geteuid());
		return 0;
	}
	if (g->user == NULL)
		bst_log(BST_LOG_WARN, "workers run as root: set \"user\"");
	if (g->user != NULL) {
		struct passwd *pw = getpwnam(g->user);
		if (pw == NULL) {
			bst_err_set(e, "user \"%s\" not found", g->user);
			return -1;
		}
		rt->uid = pw->pw_uid;
		rt->gid = pw->pw_gid;
		rt->drop_uid = rt->drop_gid = true;
		if (pw->pw_uid == 0)
			bst_log(BST_LOG_WARN, "workers run as root: user \"%s\" is uid 0", g->user);
	}
	if (g->group != NULL) {
		struct group *gr = getgrnam(g->group);
		if (gr == NULL) {
			bst_err_set(e, "group \"%s\" not found", g->group);
			return -1;
		}
		rt->gid = gr->gr_gid;
		rt->drop_gid = true;
	}
	return 0;
}

/* The lock is what makes a second server fail: with SO_REUSEPORT its bind would succeed and it
 * would quietly take half the traffic. A stale file from a crash holds no lock. */
int bst_master_open_pid_file_(master *m, bst_err *e)
{
	const char *path = m->rt.cfg->global.pid;
	if (path == NULL)
		return 0;
	int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0644);
	if (fd < 0) {
		bst_err_set(e, "pid %s: %s", path, strerror(errno));
		return -1;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		bst_err_set(e, "already running: %s is locked", path);
		close(fd);
		return -1;
	}
	char line[32];
	int n = snprintf(line, sizeof line, "%ld\n", (long)getpid());
	if (ftruncate(fd, 0) != 0 || write(fd, line, (size_t)n) != n) {
		bst_err_set(e, "pid %s: %s", path, strerror(errno));
		close(fd);
		return -1;
	}
	m->pid_fd = fd;
	return 0;
}

int bst_master_probe_backend_(master *m, bst_err *e)
{
	bst_runtime *rt = &m->rt;
	bst_io_loop_cfg(rt->cfg, &rt->loop_cfg); /* once, here: see bst_io_loop_cfg */
	rt->backend_auto = rt->loop_cfg.backend == BST_BACKEND_AUTO;
	if (bst_io_probe_cfg(&rt->loop_cfg, &rt->backend, rt->epoll_reason,
			     sizeof rt->epoll_reason, e) != 0)
		return -1;
	if (rt->backend == BST_BACKEND_EPOLL) {
		rt->loop_cfg.backend = BST_BACKEND_EPOLL;
		rt->loop_cfg.epoll_reason = rt->epoll_reason;
	}
	return 0;
}

/* An SQPOLL ring must be made after the drop, by whatever is left: see bst_child_loop_and_drop. */
int bst_master_decide_sqpoll_(master *m, bst_err *e)
{
	bst_runtime *rt = &m->rt;
	bool uid_changes = rt->drop_uid && rt->uid != 0;
	bool caps_go = geteuid() == 0 && rt->cfg->global.sandbox.drop_caps;
	if (rt->loop_cfg.uring_sqpoll == 0 || !(uid_changes || caps_go) ||
	    rt->backend != BST_BACKEND_URING)
		return 0;
	char why[192];
	if (bst_child_probe_ring_as_user(rt, why, sizeof why) == 0) {
		rt->ring_after_drop = true;
		return 0;
	}
	const char *user = uid_changes ? rt->cfg->global.user : "root without capabilities";
	if (!rt->backend_auto) {
		bst_err_set(e, "uring_sqpoll needs a ring created by user \"%s\", and that failed (%s): "
			       "add its group to kernel.io_uring_group, or unset uring_sqpoll", user, why);
		return -1;
	}
	bst_log(BST_LOG_WARN, "uring_sqpoll ignored: a ring created by user \"%s\" failed (%s), and "
		"one created by root would run every request as root. kernel.io_uring_group can "
		"allow it", user, why);
	rt->loop_cfg.uring_sqpoll = 0;
	return 0;
}

int bst_master_create_listeners_(master *m, bst_err *e)
{
	bst_runtime *rt = &m->rt;
	const bst_cfg_listen **ls;
	size_t n;
	if (bst_config_listeners(rt->cfg, &ls, &n, e) != 0)
		return -1;
	rt->listeners = calloc(n ? n : 1, sizeof *rt->listeners);
	if (rt->listeners == NULL) {
		free(ls);
		bst_err_set(e, "out of memory");
		return -1;
	}
	int rc = 0;
	for (size_t i = 0; i < n && rc == 0; i++) {
		int *fds = malloc((size_t)rt->nworkers * sizeof *fds);
		if (fds == NULL) {
			bst_err_set(e, "out of memory");
			rc = -1;
			break;
		}
		rt->listeners[i].cfg = ls[i];
		rt->listeners[i].fds = fds;
		rt->nlisteners = i + 1;
		rc = bst_listener_create(ls[i], rt->nworkers, fds, e);
		if (ls[i]->tcp != NULL && ls[i]->tcp->steering == BST_STEER_INCOMING_CPU)
			rt->pin_workers = true;
	}
	free(ls);
	return rc;
}

int bst_master_map_status_(master *m, bst_err *e)
{
	m->stats_size = (size_t)m->rt.nworkers * sizeof(bst_slot_stats);
	m->rt.stats = bst_shm_create("bastion-status", m->stats_size, &m->stats_fd);
	if (m->rt.stats == NULL) {
		bst_err_set(e, "status shared memory: %s", strerror(errno));
		return -1;
	}
	return 0;
}

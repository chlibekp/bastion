/* Master startup, step by step: everything decided once, before any fork. See master.c. */
#include "proc/master_priv.h"

#include "core/counters.h"
#include "core/log.h"
#include "core/shm.h"
#include "http/h3/quic.h"
#include "io/backend.h"
#include "io/listener.h"
#include "io/net.h"
#include "ops/numa.h"
#include "proc/channel.h"
#include "proc/helper.h"
#include "proc/reload.h"
#include "proc/runtime.h"
#include "proc/signals.h"
#include "proc/test_hooks.h"
#include "proc/upgrade.h"
#include "proc/worker.h"
#include "sec/sec.h"
#include "xdp/loader.h"
#include "xdp/reuseport.h"

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
	const bst_inherit *inh = bst_inherit_load();
	if (path == NULL) {
		if (inh->pid_fd >= 0)
			close(inh->pid_fd);
		return 0;
	}
	snprintf(m->pid_path, sizeof m->pid_path, "%s", path);
	if (inh->pid_fd >= 0) { /* a reload: the lock is already ours, through this description */
		m->pid_fd = inh->pid_fd;
		return 0;
	}
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
	/* A live upgrade's new master writes its PID once it is ready (proc/upgrade.h): until
	 * then the file is empty, which is how `bastionctl upgrade` tells the two apart. */
	if (inh->upgrade_parent > 0 ? ftruncate(fd, 0) != 0 : bst_pidfile_write(fd, getpid()) != 0) {
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

/* Every `http3` listener's group gets the sk_reuseport program (xdp/reuseport.h), here in master:
 * attaching needs CAP_BPF and CAP_NET_ADMIN, which no child keeps. A refusal falls back to the
 * kernel's hash, logged, and never fails the start. Workers with an http3 listener also need the
 * io_uring UDP buffer group, which the restricted ring cannot register later. */
static int attach_quic_routing(master *m, bst_err *e)
{
	bst_runtime *rt = &m->rt;
	size_t nq = 0;
	for (size_t i = 0; i < rt->nlisteners; i++)
		nq += rt->listeners[i].cfg->http3;
	if (nq == 0)
		return 0;
	rt->loop_cfg.uring_udp_bufs = BST_QUIC_UDP_BUFS;
	if (rt->cfg->global.quic_routing_hash) {
		bst_log(BST_LOG_INFO, "quic: quic_routing hash: a client that changes address may reach "
				      "another worker (stateless reset)");
		return 0;
	}
	m->reuseport = calloc(nq, sizeof *m->reuseport);
	uint16_t *slots = malloc((size_t)rt->nworkers * sizeof *slots);
	if (m->reuseport == NULL || slots == NULL) {
		free(slots);
		bst_err_set(e, "out of memory");
		return -1;
	}
	for (int s = 0; s < rt->nworkers; s++)
		slots[s] = (uint16_t)(rt->quic_slot_base + s);
	bst_slot_map active = { .slots = slots, .n = (size_t)rt->nworkers };
	/* Room for both halves when generations alternate; one half when they cannot. */
	uint32_t nkeys = rt->nworkers <= BST_QUIC_GEN_SLOTS ? 2 * BST_QUIC_GEN_SLOTS : (uint32_t)rt->nworkers;
	uint32_t *keys = malloc((size_t)rt->nworkers * sizeof *keys);
	m->routes = calloc(nq, sizeof *m->routes);
	if (keys == NULL || m->routes == NULL) {
		free(keys);
		free(slots);
		bst_err_set(e, "out of memory");
		return -1;
	}
	for (int s = 0; s < rt->nworkers; s++)
		keys[s] = (uint32_t)rt->quic_slot_base + (uint32_t)s;
	for (size_t i = 0; i < rt->nlisteners; i++) {
		if (!rt->listeners[i].cfg->http3)
			continue;
		bst_err why = {.msg = ""};
		bst_reuseport *r = NULL;
		int maps[3];
		/* After a reload: the attached program's maps, which still hold the draining
		 * generation's sockets at its keys; ours go in beside them. */
		if (bst_inherit_take_route(rt->listeners[i].cfg, maps)) {
			r = bst_reuseport_adopt(maps, rt->listeners[i].fds, keys, rt->nworkers, &active, &why);
			if (r == NULL) {
				for (int k = 0; k < 3; k++)
					close(maps[k]);
				bst_log(BST_LOG_WARN, "reload: quic routing hand-over failed (%s): QUIC "
						      "connections of the draining generation may be reset", why.msg);
			}
		}
		/* Fresh (first start, a new address, or a failed hand-over): replaces the group's
		 * program, so new connections always reach this generation. */
		if (r == NULL)
			r = bst_reuseport_attach_at(rt->listeners[i].fds, keys, rt->nworkers, nkeys, &active, &why);
		if (r == NULL) {
			bst_log(BST_LOG_WARN, "quic_routing ebpf unavailable (%s): using hash; a client "
					      "that changes address may reach another worker, which "
					      "resets the connection", why.msg);
			break; /* the same reason holds for every listener */
		}
		bst_inherit_route *ir = &m->routes[m->nreuseport];
		bst_inherit_key(rt->listeners[i].cfg, ir->key, sizeof ir->key);
		bst_reuseport_map_fds(r, ir->fd);
		m->reuseport[m->nreuseport++] = r;
	}
	if (m->nreuseport > 0)
		bst_log(BST_LOG_INFO, "quic: routing by connection ID over %d workers", rt->nworkers);
	free(keys);
	free(slots);
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
	/* The CPU map first: steering reads it while the sockets are made, and the workers pin by
	 * it (ops/numa.h). */
	bool steer = false;
	for (size_t i = 0; i < n; i++)
		steer |= !ls[i]->http3 && ls[i]->tcp != NULL && ls[i]->tcp->steering != BST_STEER_NONE;
	rt->pin_workers = bst_cpu_map_build(rt->cfg, steer);
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
		/* After a reload the same address keeps its sockets, queue and all: never a gap. */
		if (!bst_inherit_take_listener(ls[i], rt->nworkers, fds))
			rc = bst_listener_create(ls[i], rt->nworkers, fds, e);
	}
	free(ls);
	/* A generation's QUIC routing keys alternate halves (xdp/reuseport.h); with more workers
	 * than a half holds, every generation uses the first half and a draining one loses its
	 * routing (documented in proc/reload.h). */
	const bst_inherit *inh = bst_inherit_load();
	rt->quic_slot_base = (inh->generation & 1) && rt->nworkers <= BST_QUIC_GEN_SLOTS ? BST_QUIC_GEN_SLOTS : 0;
	if (rc == 0)
		rc = attach_quic_routing(m, e);
	if (rc == 0) /* after the routing kept the draining generation's UDP sockets in its map */
		bst_inherit_close_untaken(); /* removed addresses stop here */
	return rc;
}

/* Here in master, which keeps CAP_BPF and CAP_NET_ADMIN; no child ever has bpf(). */
int bst_master_setup_xdp_(master *m, bst_err *e)
{
	const bst_cfg_xdp *cfg = m->rt.cfg->global.xdp;
	if (cfg == NULL)
		return 0;
	int pinned = bst_xdp_adopt_pinned(cfg->pin_path);
	if (pinned > 0)
		bst_log(BST_LOG_INFO, "xdp: adopting %d pinned link(s) under %s", pinned, cfg->pin_path);
	bst_err why = { .msg = "" };
	m->xdp = bst_xdp_load(cfg, &why);
	if (m->xdp == NULL) {
		if (cfg->require) {
			bst_err_set(e, "%s", why.msg);
			return -1;
		}
		bst_log(BST_LOG_WARN, "%s: running without the XDP filter; L7 limits still apply", why.msg);
		return 0;
	}
	for (size_t i = 0; i < cfg->nifaces; i++)
		bst_log(BST_LOG_INFO, "xdp: attached to %s (%s mode)", cfg->ifaces[i], bst_xdp_mode_of(m->xdp, i));
	bst_xdp_stats_setup(m->xdp); /* counters registered before any fork */
	if (bst_sec_use_xdp(m->xdp, m->rt.cfg) != 0) { /* escalation blocks into its maps */
		bst_err_set(e, "xdp: out of memory");
		return -1;
	}
	return 0;
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

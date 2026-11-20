/* See master.h. */
#include "proc/master.h"

#include "cache/cache.h"
#include "core/counters.h"
#include "core/log.h"
#include "core/shm.h"
#include "io/backend.h"
#include "io/listener.h"
#include "http/h2/guard.h"
#include "http/h3/quic.h"
#include "xdp/loader.h"
#include "xdp/reuseport.h"
#include "io/net.h"
#include "proc/channel.h"
#include "proc/helper.h"
#include "proc/reload.h"
#include "proc/runtime.h"
#include "proc/signals.h"
#include "proc/test_hooks.h"
#include "proc/upgrade.h"
#include "proc/worker.h"
#include "tls/conn.h"
#include "tls/ktls.h"
#include "proxy/upstream.h"
#include "tls/ocsp.h"
#include "tls/early.h"
#include "tls/tickets.h"
#include "sec/sec.h"

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

#include "proc/master_priv.h"

#include "handlers/roots.h"
#include "core/addr.h"
#include "core/json.h"
#include "ops/acme.h"
#include "ops/admin.h"
#include "ops/logger.h"
#include "ops/metrics.h"
#include "ops/numa.h"
#include "sec/limit.h"

/* ---- small helpers ---- */

static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

uint64_t bst_respawn_backoff_ms(unsigned crashes)
{
	if (crashes < 2)
		return 0;
	unsigned shift = crashes - 2;
	if (shift >= 32 || ((uint64_t)BST_RESPAWN_BASE_MS << shift) >= BST_RESPAWN_MAX_MS)
		return BST_RESPAWN_MAX_MS;
	return (uint64_t)BST_RESPAWN_BASE_MS << shift;
}

static const char *child_name(const child *c, char *buf, size_t cap)
{
	if (c->slot < 0)
		snprintf(buf, cap, "helper");
	else
		snprintf(buf, cap, "worker/%d", c->slot);
	return buf;
}

static void startup_error(const master *m, const bst_err *e)
{
	/* Whoever ran us is looking at stderr. The log gets it too when it is somewhere else. */
	fprintf(stderr, "bastion: %s\n", e->msg);
	if (m->rt.cfg->global.error_log != NULL)
		bst_log(BST_LOG_ERROR, "%s", e->msg);
}

static int log_level(const char *name)
{
	if (name == NULL)
		return BST_LOG_WARN;
	static const struct { const char *n; int l; } t[] = {
		{ "debug", BST_LOG_DEBUG }, { "info", BST_LOG_INFO }, { "notice", BST_LOG_INFO },
		{ "warn", BST_LOG_WARN }, { "error", BST_LOG_ERROR },
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
		if (strcmp(name, t[i].n) == 0)
			return t[i].l;
	return BST_LOG_WARN;
}

/* ---- start: everything decided once, before any fork ---- */

static int open_logs(master *m, bst_err *e)
{
	const bst_cfg_global *g = &m->rt.cfg->global;
	m->rt.log_level = log_level(g->error_log_level);
	m->rt.log_base_fd = bst_logsink_open(g->error_log, e);
	if (m->rt.log_base_fd < 0)
		return -1;
	m->rt.log_inherited = bst_logsink_attach(m->rt.log_base_fd, m->rt.log_level);
	if (m->rt.log_inherited < 0)
		fputs("bastion: warning: no non-blocking way to write the error log (a tty this user "
		      "cannot reopen, or no /proc): log lines are dropped, crash reports too; set "
		      "error_log to a file\n", stderr);
	return 0;
}

/* ---- children ---- */

static void close_for_child(master *m, const child *self)
{
	close(m->sigfd);
	if (m->pid_fd >= 0)
		close(m->pid_fd);
	if (m->stats_fd >= 0)
		close(m->stats_fd);
	if (m->rt.pidns_fd >= 0)
		close(m->rt.pidns_fd);
	/* A sibling holding master's end of a channel would hide master's death from that child. */
	for (int i = 0; i < m->nkids; i++)
		if (&m->kids[i] != self && m->kids[i].chan >= 0)
			close(m->kids[i].chan);
	for (size_t i = 0; i < m->nolds; i++)
		if (m->olds[i].chan >= 0)
			close(m->olds[i].chan);
}

static int spawn(master *m, child *c)
{
	char name[32];
	int sv[2];
	if (bst_chan_pair(sv) != 0)
		return -errno;
	pid_t pid = bst_ns_fork(&m->rt);
	if (pid < 0) {
		int rc = -errno;
		close(sv[0]);
		close(sv[1]);
		return rc;
	}
	if (pid == 0) {
		close(sv[0]);
		close_for_child(m, c);
		m->rt.channel = sv[1];
		if (c->slot >= 0)
			bst_worker_main(c->slot, &m->rt);
		bst_helper_main(&m->rt);
	}
	close(sv[1]);
	c->pid = pid;
	c->chan = sv[0];
	c->ready = c->replacing = false;
	c->started_ms = now_ms();
	c->respawn_at = c->eof_at = c->kill_at = 0;
	bst_log(BST_LOG_INFO, "%s started, pid %ld", child_name(c, name, sizeof name), (long)pid);
	return 0;
}

static void kill_child(const child *c)
{
	if (c->pid > 0)
		kill(c->pid, SIGKILL); /* pid is unreaped, so it is still ours */
}

static void close_chan(child *c)
{
	if (c->chan >= 0)
		close(c->chan);
	c->chan = -1;
}

/* Workers first; the helper hears of a graceful stop once they are gone (later phases give
 * workers things to hand it on their way out). */
static void tell_stop(child *c, bool graceful)
{
	if (c->pid <= 0 || c->chan < 0)
		return;
	bst_msg m = {.type = BST_MSG_STOP, .stop = {.graceful = graceful}};
	(void)bst_chan_send(c->chan, &m); /* full or broken: the deadline deals with this child */
}

static void close_listeners(master *m)
{
	for (size_t i = 0; i < m->rt.nlisteners; i++)
		for (int s = 0; s < m->rt.nworkers; s++)
			if (m->rt.listeners[i].fds != NULL && m->rt.listeners[i].fds[s] >= 0) {
				close(m->rt.listeners[i].fds[s]);
				m->rt.listeners[i].fds[s] = -1;
			}
}

static void begin_stop(master *m, bool graceful)
{
	if (m->state == STOP_FAST || (m->state == STOP_GRACEFUL && graceful))
		return;
	m->state = graceful ? STOP_GRACEFUL : STOP_FAST;
	bst_acme_master_stop();
	m->deadline = now_ms() + (graceful ? m->rt.cfg->global.shutdown_timeout_ms
					   : BST_FAST_STOP_MS);
	bst_log(BST_LOG_INFO, "%s stop", graceful ? "graceful" : "fast");
	for (int i = 0; i < m->nkids; i++) {
		child *c = &m->kids[i];
		c->respawn_at = 0;
		if (c->slot >= 0 || !graceful)
			tell_stop(c, graceful);
	}
	if (!graceful)
		m->helper_told = true;
	for (size_t i = 0; i < m->nolds; i++) /* a generation still draining from a reload */
		tell_stop(&m->olds[i], graceful);
	/* Workers hold their own copies until they have emptied the queues. */
	close_listeners(m);
}

/* A worker reports a backend other than the one everybody must run. Under auto the only way is
 * down: move every worker to epoll. */
static void move_all_to_epoll(master *m, const child *from)
{
	char name[32];
	bst_runtime *rt = &m->rt;
	rt->backend = BST_BACKEND_EPOLL;
	rt->loop_cfg.backend = BST_BACKEND_EPOLL;
	snprintf(rt->epoll_reason, sizeof rt->epoll_reason, "%s could not use io_uring",
		 child_name(from, name, sizeof name));
	rt->loop_cfg.epoll_reason = rt->epoll_reason;
	bst_log(BST_LOG_WARN, "%s: moving every worker to epoll", rt->epoll_reason);
	uint64_t deadline = now_ms() + rt->cfg->global.shutdown_timeout_ms;
	for (int i = 0; i < rt->nworkers; i++) {
		child *c = &m->kids[i];
		if (c == from || c->pid <= 0 || !c->ready)
			continue; /* one not ready yet is checked when its READY comes */
		c->ready = false;
		c->replacing = true;
		c->kill_at = deadline;
		tell_stop(c, true);
	}
}

static void bad_message(child *c)
{
	char name[32];
	bst_log(BST_LOG_ERROR, "%s (pid %ld) sent a bad channel message: killing it",
		child_name(c, name, sizeof name), (long)c->pid);
	kill_child(c);
	close_chan(c);
}

/* ---- reload (proc/reload.h) ---- */

/* The new generation is ready: the old one stops accepting and finishes what it has. */
static void drain_olds(master *m)
{
	if (m->olds_told)
		return;
	m->olds_told = true;
	size_t n = 0;
	for (size_t i = 0; i < m->nolds; i++)
		if (m->olds[i].pid > 0) {
			tell_stop(&m->olds[i], true);
			n++;
		}
	if (m->nolds == 0 && (m->generation == 0 || m->upgrade_parent > 0))
		return; /* a first start, or a live upgrade's new master: nothing was reloaded */
	if (n > 0)
		m->olds_deadline = now_ms() + m->rt.cfg->global.shutdown_timeout_ms;
	bst_reload_set_status("ok");
	bst_log(BST_LOG_INFO, "reload: generation %u ready, draining %zu old process(es)",
		m->generation, n);
}

static void adopt_olds(master *m, const bst_inherit *inh)
{
	m->generation = inh->generation;
	if (inh->nolds == 0)
		return;
	m->olds = calloc(inh->nolds, sizeof *m->olds);
	if (m->olds == NULL) { /* they still drain: PDEATHSIG ends them with master at worst */
		bst_log(BST_LOG_ERROR, "reload: out of memory: the old generation is not supervised");
		return;
	}
	for (size_t i = 0; i < inh->nolds; i++)
		m->olds[i] = (child){.pid = inh->olds[i].pid, .chan = inh->olds[i].chan,
				     .slot = inh->olds[i].slot, .ready = true};
	m->nolds = inh->nolds;
}

static bool reap_old(master *m, pid_t pid)
{
	char name[32];
	for (size_t i = 0; i < m->nolds; i++) {
		child *c = &m->olds[i];
		if (c->pid != pid)
			continue;
		bst_log(BST_LOG_INFO, "old %s (pid %ld) exited", child_name(c, name, sizeof name), (long)pid);
		c->pid = 0;
		close_chan(c);
		return true;
	}
	return false;
}

/* Validates the configuration for a reload: 0, or -1 with the status set and why filled. */
static int reload_check(char *why, size_t cap)
{
	bst_log(BST_LOG_INFO, "reload: checking the configuration");
	if (bst_reload_validate(-1, why, cap) != 0) {
		bst_metrics_reload_result(false);
		bst_reload_set_status("failed: %s", why);
		bst_log(BST_LOG_ERROR, "reload failed, still serving the old configuration: %s", why);
		return -1;
	}
	return 0;
}

/* checked: the admin API already ran reload_check. */
static void do_reload_checked(master *m, bool checked)
{
	char why[512];
	if (m->state != RUNNING)
		return;
	if (!m->announced) {
		m->reload_pending = true; /* one more, once this generation is ready */
		bst_log(BST_LOG_INFO, "reload: requested while generation %u starts: coalesced",
			m->generation);
		return;
	}
	if (!checked && reload_check(why, sizeof why) != 0)
		return;
	/* Every live process is handed over: this generation and any still draining. Past the cap,
	 * the oldest are killed so generations cannot pile up. */
	size_t cap = (size_t)m->nkids + m->nolds;
	bst_inherit_child *kids = calloc(cap ? cap : 1, sizeof *kids);
	int **lfds = calloc(m->rt.nlisteners ? m->rt.nlisteners : 1, sizeof *lfds);
	const bst_cfg_listen **lcfg = calloc(m->rt.nlisteners ? m->rt.nlisteners : 1, sizeof *lcfg);
	char *val = NULL;
	if (kids == NULL || lfds == NULL || lcfg == NULL)
		goto oom;
	size_t nk = 0, live = 0;
	for (int i = 0; i < m->nkids; i++)
		live += m->kids[i].pid > 0;
	for (size_t i = 0; i < m->nolds; i++)
		live += m->olds[i].pid > 0;
	size_t drop = live > BST_RELOAD_MAX_OLD ? live - BST_RELOAD_MAX_OLD : 0;
	for (size_t i = 0; i < m->nolds; i++) {
		child *c = &m->olds[i];
		if (c->pid <= 0)
			continue;
		if (drop > 0) {
			drop--;
			bst_log(BST_LOG_WARN, "reload: too many generations: killing old pid %ld", (long)c->pid);
			kill_child(c);
			continue; /* reaped by the next image as an unknown child */
		}
		kids[nk++] = (bst_inherit_child){.pid = c->pid, .chan = c->chan, .slot = c->slot};
	}
	for (int i = 0; i < m->nkids; i++)
		if (m->kids[i].pid > 0)
			kids[nk++] = (bst_inherit_child){.pid = m->kids[i].pid, .chan = m->kids[i].chan,
							 .slot = m->kids[i].slot};
	for (size_t i = 0; i < m->rt.nlisteners; i++) {
		lcfg[i] = m->rt.listeners[i].cfg;
		lfds[i] = m->rt.listeners[i].fds;
	}
	bst_inherit_out out = {.generation = m->generation + 1, .pid_fd = m->pid_fd,
			       .lcfg = lcfg, .lfds = lfds, .nlisteners = m->rt.nlisteners,
			       .nslots = m->rt.nworkers, .kids = kids, .nkids = nk,
			       .routes = m->routes, .nroutes = m->nreuseport,
			       /* still an uncommitted upgrade's new master: the next image is too */
			       .upgrade_parent = m->upgrade_parent > 0 && getppid() == m->upgrade_parent
				       ? m->upgrade_parent : 0};
	val = bst_inherit_encode(&out);
	if (val == NULL)
		goto oom;
	bst_log(BST_LOG_INFO, "reload: configuration ok, starting generation %u", m->generation + 1);
	bst_acme_master_stop(); /* the next image starts its own job, on its own challenge table */
	bst_reload_exec(-1, val);
	bst_acme_master_ready(m->rt.cfg, now_ms());
	bst_metrics_reload_result(false);
	bst_reload_set_status("failed: exec: %s", strerror(errno));
	bst_log(BST_LOG_ERROR, "reload failed, still serving the old configuration: exec: %s",
		strerror(errno));
	goto out;
oom:
	bst_metrics_reload_result(false);
	bst_reload_set_status("failed: out of memory");
	bst_log(BST_LOG_ERROR, "reload failed, still serving the old configuration: out of memory");
out:
	free(val);
	free(kids);
	free(lfds);
	free(lcfg);
}

/* ---- live upgrade (proc/upgrade.h) ---- */

static void oldbin_path(const master *m, char *buf, size_t cap)
{
	snprintf(buf, cap, "%s.oldbin", m->rt.cfg->global.pid);
}

/* Moves our PID file aside for the new master's, or back. 0, or -1 (errno). */
static int pidfile_move(master *m, bool aside)
{
	const char *path = m->rt.cfg->global.pid;
	if (path == NULL || m->pid_fd < 0)
		return 0;
	char ob[sizeof m->pid_path];
	oldbin_path(m, ob, sizeof ob);
	const char *from = aside ? path : ob, *to = aside ? ob : path;
	if (!bst_pidfile_is(m->pid_fd, from))
		return 0; /* not where we left it: nothing of ours to move */
	if (rename(from, to) != 0)
		return -1;
	snprintf(m->pid_path, sizeof m->pid_path, "%s", to);
	return 0;
}

/* QUIC: the active routing slots back to this generation's keys (the new master moved them). */
static void quic_take_back(master *m)
{
	if (m->nreuseport == 0)
		return;
	uint16_t *slots = malloc((size_t)m->rt.nworkers * sizeof *slots);
	if (slots == NULL) {
		bst_log(BST_LOG_ERROR, "upgrade: out of memory: QUIC routing stays with the new master");
		return;
	}
	for (int s = 0; s < m->rt.nworkers; s++)
		slots[s] = (uint16_t)(m->rt.quic_slot_base + s);
	bst_slot_map active = {.slots = slots, .n = (size_t)m->rt.nworkers};
	for (size_t i = 0; i < m->nreuseport; i++) {
		bst_err why = {.msg = ""};
		if (bst_reuseport_set_active(m->reuseport[i], &active, &why) != 0)
			bst_log(BST_LOG_ERROR, "upgrade: cannot take QUIC routing back: %s", why.msg);
	}
	free(slots);
}

/* After a rollback or a failed new master: this master serves alone again. */
static void upgrade_restore(master *m)
{
	char name[32], state[48];
	if (m->winched) {
		m->winched = false;
		for (int i = 0; i < m->rt.nworkers; i++) {
			child *c = &m->kids[i];
			if (c->pid > 0) {
				c->replacing = true; /* still draining: replaced as soon as it exits */
				continue;
			}
			int rc = spawn(m, c);
			if (rc != 0) {
				bst_log(BST_LOG_ERROR, "%s: respawn: %s", child_name(c, name, sizeof name),
					strerror(-rc));
				c->respawn_at = now_ms() + BST_RESPAWN_BASE_MS;
			}
		}
	}
	(void)bst_xdp_take_back(m->xdp);
	quic_take_back(m);
	if (pidfile_move(m, false) != 0)
		bst_log(BST_LOG_ERROR, "upgrade: cannot rename the PID file back to %s: %s",
			m->rt.cfg->global.pid, strerror(errno));
	snprintf(state, sizeof state, "MAINPID=%ld", (long)getpid());
	(void)bst_upgrade_notify(state);
}

static void upgrade_refused(const char *why)
{
	bst_reload_set_status("failed: upgrade: %s", why);
	bst_log(BST_LOG_ERROR, "upgrade refused, still serving with this binary: %s", why);
}

static void do_upgrade(master *m)
{
	char why[512];
	if (m->state != RUNNING)
		return;
	if (m->upgrade_pid > 0) {
		bst_log(BST_LOG_WARN, "upgrade: already in progress (new master pid %ld): USR2 ignored",
			(long)m->upgrade_pid);
		return;
	}
	if (m->upgrade_parent > 0 && getppid() == m->upgrade_parent) {
		bst_log(BST_LOG_WARN, "upgrade: refused: this master's own upgrade is not committed yet");
		return;
	}
	if (!m->announced) {
		bst_log(BST_LOG_WARN, "upgrade: refused while this master is still starting");
		return;
	}
	bst_log(BST_LOG_INFO, "upgrade: checking %s", bst_upgrade_exe());
	int fd = bst_upgrade_open_binary(why, sizeof why);
	if (fd < 0) {
		upgrade_refused(why);
		return;
	}
	if (bst_reload_validate(fd, why, sizeof why) != 0) {
		close(fd);
		upgrade_refused(why);
		return;
	}
	int **lfds = calloc(m->rt.nlisteners ? m->rt.nlisteners : 1, sizeof *lfds);
	const bst_cfg_listen **lcfg = calloc(m->rt.nlisteners ? m->rt.nlisteners : 1, sizeof *lcfg);
	char *val = NULL;
	if (lfds != NULL && lcfg != NULL) {
		for (size_t i = 0; i < m->rt.nlisteners; i++) {
			lcfg[i] = m->rt.listeners[i].cfg;
			lfds[i] = m->rt.listeners[i].fds;
		}
	}
	/* No PID file and no children: the new master locks its own file and runs its own
	 * workers, while ours keep serving until WINCH. */
	bst_inherit_out out = {.generation = m->generation + 1, .pid_fd = -1, .lcfg = lcfg,
			       .lfds = lfds, .nlisteners = m->rt.nlisteners, .nslots = m->rt.nworkers,
			       .routes = m->routes, .nroutes = m->nreuseport, .upgrade_parent = getpid()};
	if (lfds != NULL && lcfg != NULL)
		val = bst_inherit_encode(&out);
	pid_t pid = -1;
	if (val == NULL) {
		snprintf(why, sizeof why, "out of memory");
	} else if (pidfile_move(m, true) != 0) {
		snprintf(why, sizeof why, "cannot rename the PID file to .oldbin: %s", strerror(errno));
	} else {
		pid = fork();
		if (pid == 0) {
			sigset_t none;
			sigemptyset(&none);
			sigprocmask(SIG_SETMASK, &none, NULL);
			bst_reload_exec(fd, val);
			_exit(127);
		}
		if (pid < 0) {
			snprintf(why, sizeof why, "fork: %s", strerror(errno));
			(void)pidfile_move(m, false);
		}
	}
	if (val != NULL)
		bst_inherit_encoded_cloexec(&out); /* ours again: later workers must not leak them */
	close(fd);
	free(val);
	free(lfds);
	free(lcfg);
	if (pid < 0) {
		upgrade_refused(why);
		return;
	}
	m->upgrade_pid = pid;
	m->rolling_back = m->winched = false;
	bst_reload_set_status("upgrading: new master pid %ld", (long)pid);
	bst_log(BST_LOG_INFO, "upgrade: new master started, pid %ld", (long)pid);
}

static void do_winch(master *m)
{
	char name[32];
	if (m->upgrade_pid <= 0 || m->rolling_back) {
		bst_log(BST_LOG_WARN, "WINCH ignored: no upgrade in progress");
		return;
	}
	if (m->winched || m->state != RUNNING)
		return;
	m->winched = true;
	uint64_t deadline = now_ms() + m->rt.cfg->global.shutdown_timeout_ms;
	int n = 0;
	for (int i = 0; i < m->rt.nworkers; i++) {
		child *c = &m->kids[i];
		c->respawn_at = 0;
		if (c->pid <= 0)
			continue;
		c->replacing = false;
		c->kill_at = deadline;
		tell_stop(c, true);
		n++;
		bst_log(BST_LOG_DEBUG, "upgrade: draining %s", child_name(c, name, sizeof name));
	}
	bst_log(BST_LOG_INFO, "upgrade: draining %d old worker(s); HUP rolls back, QUIT commits", n);
}

static void quit_new(master *m);

static void do_rollback(master *m)
{
	if (m->rolling_back || m->state != RUNNING)
		return;
	m->rolling_back = true;
	bool respawned = m->winched;
	bst_log(BST_LOG_INFO, "upgrade: rolling back: new master pid %ld stops %s",
		(long)m->upgrade_pid, respawned ? "once our workers are ready" : "now");
	upgrade_restore(m);
	/* As on a reload, the generation leaving stops accepting only once the one serving is
	 * ready: the same sockets, so nothing waits in a queue nobody accepts from. */
	uint64_t window = BST_STARTUP_DEADLINE_MS;
#ifdef BST_TEST
	window = bst_test_startup_deadline(window);
#endif
	m->quit_new_at = now_ms() + window;
	if (!respawned)
		quit_new(m);
	bst_reload_set_status("rolled back");
}

static bool workers_ready(const master *m)
{
	for (int i = 0; i < m->rt.nworkers; i++)
		if (!m->kids[i].ready)
			return false;
	return true;
}

static void quit_new(master *m)
{
	if (m->quit_new_at == 0 || m->upgrade_pid <= 0)
		return;
	m->quit_new_at = 0;
	if (!workers_ready(m))
		bst_log(BST_LOG_WARN, "upgrade: rollback: stopping the new master before every worker "
				      "of ours is ready");
	kill(m->upgrade_pid, SIGQUIT); /* our child, unreaped: still that process */
}

static void do_commit(master *m)
{
	char state[48];
	if (m->upgrade_pid <= 0 || m->rolling_back)
		return;
	bst_log(BST_LOG_INFO, "upgrade: committed: new master pid %ld takes over",
		(long)m->upgrade_pid);
	snprintf(state, sizeof state, "MAINPID=%ld", (long)m->upgrade_pid);
	(void)bst_upgrade_notify(state);
}

/* The new master exited while we still run. */
static void on_upgrade_exit(master *m, int st)
{
	char how[96];
	pid_t pid = m->upgrade_pid;
	m->upgrade_pid = 0;
	m->quit_new_at = 0;
	if (m->rolling_back) {
		m->rolling_back = false;
		bst_log(BST_LOG_INFO, "upgrade: rolled back: new master (pid %ld) exited", (long)pid);
		return;
	}
	if (WIFEXITED(st) && WEXITSTATUS(st) == BST_EXIT_STATE)
		snprintf(how, sizeof how, "refused the handed-over state (incompatible format)");
	else if (WIFEXITED(st) && WEXITSTATUS(st) == 127)
		snprintf(how, sizeof how, "could not be executed");
	else if (WIFSIGNALED(st))
		snprintf(how, sizeof how, "was killed by signal %d", WTERMSIG(st));
	else
		snprintf(how, sizeof how, "exited with status %d", WEXITSTATUS(st));
	bst_reload_set_status("failed: upgrade: new master %s", how);
	if (m->state != RUNNING) {
		bst_log(BST_LOG_INFO, "upgrade: new master (pid %ld) %s", (long)pid, how);
		return;
	}
	bst_log(BST_LOG_ERROR, "upgrade failed: new master (pid %ld) %s; still serving with this "
			       "binary", (long)pid, how);
	upgrade_restore(m);
}

/* In the new master: every worker is ready, so the PID file names us now. */
static void upgrade_ready(master *m)
{
	if (m->upgrade_parent <= 0)
		return;
	if (m->pid_fd >= 0 && bst_pidfile_write(m->pid_fd, getpid()) != 0)
		bst_log(BST_LOG_ERROR, "upgrade: cannot write the PID file: %s", strerror(errno));
	bst_log(BST_LOG_INFO, "upgrade: new master ready, pid %ld (old master pid %ld)",
		(long)getpid(), (long)m->upgrade_parent);
}

static void on_ready(master *m, child *c, bst_backend b)
{
	char name[32];
	bst_runtime *rt = &m->rt;
	if (c->ready || c->replacing) { /* one READY per process; a drain has nothing to report */
		bad_message(c);
		return;
	}
	if (c->slot >= 0 && b != rt->backend) {
		if (!rt->backend_auto) {
			bad_message(c); /* configured uring or epoll: a worker cannot have the other */
			return;
		}
		if (b != BST_BACKEND_EPOLL) { /* forked before the move to epoll */
			c->replacing = true;
			c->kill_at = now_ms() + rt->cfg->global.shutdown_timeout_ms;
			tell_stop(c, true);
			return;
		}
		move_all_to_epoll(m, c);
	}
	c->ready = true;
	bst_log(BST_LOG_INFO, "%s ready", child_name(c, name, sizeof name));
	if (m->quit_new_at != 0 && workers_ready(m)) /* a rollback's workers: the new master goes */
		quit_new(m);
	if (m->announced || m->state != RUNNING)
		return;
	for (int i = 0; i < m->nkids; i++) /* the helper counts: its startup can fail too */
		if (!m->kids[i].ready)
			return;
	m->started = m->announced = true;
	m->startup_deadline = 0;
	bst_log(BST_LOG_INFO, "ready: %d workers on %s", rt->nworkers, bst_backend_name(rt->backend));
	bst_acme_master_ready(rt->cfg, now_ms());
	upgrade_ready(m);
	drain_olds(m);
	if (m->reload_pending) {
		m->reload_pending = false;
		do_reload_checked(m, false);
	}
}

/* ---- the admin API (ops/admin.h): the helper's requests through the mailbox ---- */

static void admin_json(unsigned seq, int status, bst_jw *w)
{
	if (bst_jw_finish(w))
		bst_admin_answer(seq, status, w->buf, w->len);
	else
		bst_admin_answer(seq, 500, "{\"error\":\"out of memory\"}", 25);
	bst_jw_free(w);
}

static void admin_msg(unsigned seq, int status, const char *key, const char *msg)
{
	bst_jw w;
	bst_jw_init(&w);
	bst_jw_obj_begin(&w);
	bst_jw_key(&w, (bst_str){ key, (uint32_t)strlen(key) });
	bst_jw_str_lossy(&w, (bst_str){ msg, (uint32_t)strlen(msg) });
	bst_jw_obj_end(&w);
	admin_json(seq, status, &w);
}

static void admin_status(master *m, unsigned seq)
{
	bst_jw w;
	const char *rs = bst_reload_status();
	bst_jw_init(&w);
	bst_jw_obj_begin(&w);
	bst_jw_key(&w, BST_S("pid"));
	bst_jw_int(&w, (int64_t)getpid());
	bst_jw_key(&w, BST_S("generation"));
	bst_jw_int(&w, (int64_t)m->generation);
	bst_jw_key(&w, BST_S("workers"));
	bst_jw_int(&w, (int64_t)m->rt.nworkers);
	bst_jw_key(&w, BST_S("ready"));
	bst_jw_bool(&w, m->announced);
	bst_jw_key(&w, BST_S("reload"));
	bst_jw_str_lossy(&w, (bst_str){ rs, (uint32_t)strlen(rs) });
	bst_jw_key(&w, BST_S("upgrading"));
	bst_jw_bool(&w, m->upgrade_pid > 0);
	bst_jw_obj_end(&w);
	admin_json(seq, 200, &w);
}

#define ADMIN_LIST_MAX 16384u /* blocks listed, at most (the rest: "truncated") */

static void admin_blocks(unsigned seq)
{
	bst_block_entry *v = calloc(ADMIN_LIST_MAX + 1, sizeof *v);
	if (v == NULL) {
		admin_msg(seq, 500, "error", "out of memory");
		return;
	}
	size_t n = bst_sec_admin_list(v, ADMIN_LIST_MAX + 1);
	bool trunc = n > ADMIN_LIST_MAX;
	if (trunc)
		n = ADMIN_LIST_MAX;
	uint64_t now = bst_limit_now_us();
	bst_jw w;
	bst_jw_init(&w);
	bst_jw_obj_begin(&w);
	bst_jw_key(&w, BST_S("blocks"));
	bst_jw_arr_begin(&w);
	for (size_t i = 0; i < n; i++) {
		char a[BST_ADDR_STRLEN];
		size_t al = bst_addr_format(&v[i].ip, a, sizeof a);
		bst_jw_obj_begin(&w);
		bst_jw_key(&w, BST_S("addr"));
		bst_jw_str(&w, (bst_str){ a, (uint32_t)al });
		bst_jw_key(&w, BST_S("prefix"));
		bst_jw_int(&w, v[i].prefix);
		bst_jw_key(&w, BST_S("ttl"));
		bst_jw_int(&w, v[i].expires_us > now ? (int64_t)((v[i].expires_us - now) / 1000000u) : 0);
		bst_jw_key(&w, BST_S("l7_only"));
		bst_jw_bool(&w, (v[i].flags & BST_BLOCK_L7) != 0);
		bst_jw_obj_end(&w);
	}
	bst_jw_arr_end(&w);
	bst_jw_key(&w, BST_S("truncated"));
	bst_jw_bool(&w, trunc);
	bst_jw_obj_end(&w);
	free(v);
	admin_json(seq, 200, &w);
}

static void admin_block(const bst_admin_req *r, unsigned seq, bool add)
{
	bst_ip ip;
	memset(&ip, 0, sizeof ip);
	ip.family = r->family == 4 ? BST_IP_V4 : BST_IP_V6;
	memcpy(ip.b, r->addr, 16);
	char a[BST_ADDR_STRLEN], msg[160];
	(void)bst_addr_format(&ip, a, sizeof a);
	if (!add) {
		int rc = bst_sec_admin_unblock(&ip, r->prefix);
		if (rc > 0)
			bst_log(BST_LOG_WARN, "admin: unblocked %s/%u (uid %lu)", a, r->prefix,
				(unsigned long)r->peer_uid);
		snprintf(msg, sizeof msg, "%s/%u %s", a, r->prefix,
			 rc > 0 ? "unblocked" : rc == 0 ? "is not blocked" : "no block list");
		admin_msg(seq, rc > 0 ? 200 : rc == 0 ? 404 : 503, rc > 0 ? "status" : "error", msg);
		return;
	}
	bst_block_rc rc = bst_sec_admin_block(&ip, r->prefix, r->ttl_us);
	int st = 200;
	switch (rc) {
	case BST_BLOCK_ADDED:
	case BST_BLOCK_EXTENDED:
		bst_log(BST_LOG_WARN, "admin: blocked %s/%u for %llus (uid %lu)", a, r->prefix,
			(unsigned long long)(r->ttl_us / 1000000u), (unsigned long)r->peer_uid);
		snprintf(msg, sizeof msg, "%s/%u blocked for %llus", a, r->prefix,
			 (unsigned long long)(r->ttl_us / 1000000u));
		break;
	case BST_BLOCK_MALFORMED:
		st = 400;
		snprintf(msg, sizeof msg, "%s/%u: only single addresses (IPv4 /32, IPv6 /48 to /128) "
			 "for 1 s to 1 day", a, r->prefix);
		break;
	case BST_BLOCK_EXEMPT:
		st = 409;
		snprintf(msg, sizeof msg, "%s is allowlisted (escalation_allow, a trusted proxy, "
			 "loopback, xdp allow or an upstream): refused", a);
		break;
	case BST_BLOCK_CEILING:
		st = 409;
		snprintf(msg, sizeof msg, "escalation_ceiling reached: %s not blocked", a);
		break;
	default:
		st = 503;
		snprintf(msg, sizeof msg, "the block backend refused %s", a);
		break;
	}
	admin_msg(seq, st, st == 200 ? "status" : "error", msg);
}

static void admin_request(master *m, child *c, unsigned seq)
{
	bst_admin_req r;
	bool reload_after = false;
	if (!bst_admin_take(seq, &r)) {
		admin_msg(seq, 400, "error", "malformed request"); /* a stale seq is ignored by the helper */
		r.op = 0;
	}
	switch (r.op) {
	case 0:
		break;
	case BST_ADMIN_STATUS:
		admin_status(m, seq);
		break;
	case BST_ADMIN_RELOAD: {
		char why[512];
		bst_log(BST_LOG_INFO, "admin: reload requested (pid %ld uid %lu)", (long)r.peer_pid,
			(unsigned long)r.peer_uid);
		if (m->state != RUNNING || m->upgrade_pid > 0)
			admin_msg(seq, 409, "error", "not now: stopping or upgrading");
		else if (!m->announced)
			admin_msg(seq, 409, "error", "a generation is still starting: retry");
		else if (reload_check(why, sizeof why) != 0)
			admin_msg(seq, 400, "error", why);
		else {
			admin_msg(seq, 202, "status", "configuration ok: reloading");
			reload_after = true;
		}
		break;
	}
	case BST_ADMIN_UPGRADE: {
		bst_log(BST_LOG_INFO, "admin: upgrade requested (pid %ld uid %lu)", (long)r.peer_pid,
			(unsigned long)r.peer_uid);
		pid_t before = m->upgrade_pid;
		do_upgrade(m);
		const char *st = bst_reload_status();
		if (m->upgrade_pid > 0 && m->upgrade_pid != before)
			admin_msg(seq, 202, "status", st);
		else
			admin_msg(seq, 409, "error", strncmp(st, "failed", 6) == 0 ? st : "upgrade refused (see the log)");
		break;
	}
	case BST_ADMIN_BLOCKS:
		admin_blocks(seq);
		break;
	case BST_ADMIN_BLOCK:
	case BST_ADMIN_UNBLOCK:
		admin_block(&r, seq, r.op == BST_ADMIN_BLOCK);
		break;
	default:
		return;
	}
	bst_msg done = {.type = BST_MSG_ADMIN_DONE, .admin = {.seq = seq}};
	if (c->chan >= 0 && bst_chan_send(c->chan, &done) != 0)
		bst_log(BST_LOG_WARN, "admin: cannot answer the helper");
	if (reload_after)
		do_reload_checked(m, true);
}

static void read_channel(master *m, child *c)
{
	for (unsigned k = 0; k < BST_CHAN_BUDGET && c->chan >= 0; k++) {
		bst_msg msg;
		int rc = bst_chan_recv(c->chan, &msg);
		if (rc == -EAGAIN)
			return;
		if (rc == 1 && msg.type == BST_MSG_READY) {
			on_ready(m, c, msg.ready.backend);
		} else if (rc == 1 && msg.type == BST_MSG_ADMIN && c->slot < 0 &&
			   c >= m->kids && c < m->kids + m->nkids) { /* this generation's helper only */
			admin_request(m, c, msg.admin.seq);
		} else if (rc == 0) {
			close_chan(c); /* normally the child is dying: the reap comes next */
			c->eof_at = now_ms();
		} else {
			bad_message(c);
		}
	}
}

static void on_child_exit(master *m, child *c, int st)
{
	char name[32], how[48];
	pid_t pid = c->pid;
	bool first_start = !m->started;
	child_name(c, name, sizeof name);
	c->pid = 0;
	c->ready = false;
	close_chan(c);
	bst_logger_worker_exited(c->slot); /* the helper waits for no more of its lines */
	c->eof_at = c->kill_at = 0;
	if (m->state != RUNNING) {
		bst_log(BST_LOG_INFO, "%s (pid %ld) exited", name, (long)pid);
		return;
	}
	if (m->winched && c->slot >= 0 && !c->replacing) { /* drained for a live upgrade */
		bst_log(BST_LOG_INFO, "%s (pid %ld) drained for the upgrade", name, (long)pid);
		return;
	}
	if (c->replacing) {
		c->replacing = false;
		int rc = spawn(m, c);
		if (rc == 0)
			return;
		bst_log(BST_LOG_ERROR, "%s: respawn: %s", name, strerror(-rc));
	}
	if (first_start && WIFEXITED(st) && WEXITSTATUS(st) == BST_EXIT_STARTUP) {
		bst_log(BST_LOG_ERROR, "startup failed: %s (pid %ld) could not start", name, (long)pid);
		m->failed = true;
		begin_stop(m, false);
		return;
	}
	if (WIFSIGNALED(st))
		snprintf(how, sizeof how, "killed by signal %d", WTERMSIG(st));
	else
		snprintf(how, sizeof how, "exited with status %d", WEXITSTATUS(st));
	uint64_t now = now_ms(), stable = BST_RESPAWN_STABLE_MS;
#ifdef BST_TEST
	stable = bst_test_stable_ms(stable);
#endif
	if (now - c->started_ms >= stable)
		c->crashes = 0;
	if (c->crashes < UINT32_MAX)
		c->crashes++;
	bst_counter_add(m->crash_ctr, 1);
	bst_metrics_worker_restart(); /* every crash is followed by a respawn, now or after backoff */
	uint64_t backoff = bst_respawn_backoff_ms(c->crashes), real = backoff;
#ifdef BST_TEST
	real = bst_test_respawn_delay(backoff);
#endif
	bst_log(BST_LOG_ERROR, "%s (pid %ld) %s; respawn after backoff_ms=%llu (crash %u)", name,
		(long)pid, how, (unsigned long long)backoff, c->crashes);
	if (backoff > 0 && c->slot >= 0)
		bst_log(BST_LOG_ERROR, "slot %d has no worker for backoff_ms=%llu: connections hashing "
			"to it wait in its accept queue", c->slot, (unsigned long long)backoff);
	if (real > 0) {
		c->respawn_at = now + real;
		return;
	}
	int rc = spawn(m, c);
	if (rc != 0) {
		bst_log(BST_LOG_ERROR, "%s: respawn: %s", name, strerror(-rc));
		c->respawn_at = now + BST_RESPAWN_BASE_MS;
	}
}

static void reap(master *m)
{
	for (;;) {
		int st;
		pid_t pid = waitpid(-1, &st, WNOHANG);
		if (pid <= 0)
			return;
		if (m->upgrade_pid > 0 && pid == m->upgrade_pid) {
			on_upgrade_exit(m, st);
			continue;
		}
		int acme = bst_acme_master_reaped(pid, st, now_ms());
		if (acme >= 0) {
			if (acme == 1) { /* a new certificate: the reload path of any certificate change */
				bst_log(BST_LOG_INFO, "acme: new certificate: reloading");
				do_reload_checked(m, false);
			}
			continue;
		}
		if (reap_old(m, pid))
			continue;
		for (int i = 0; i < m->nkids; i++)
			if (m->kids[i].pid == pid) {
				on_child_exit(m, &m->kids[i], st);
				break;
			}
	}
}

static void read_signals(master *m)
{
	struct signalfd_siginfo si;
	while (read(m->sigfd, &si, sizeof si) == (ssize_t)sizeof si) {
		switch ((int)si.ssi_signo) {
		case SIGTERM:
		case SIGINT:
			begin_stop(m, false);
			break;
		case SIGQUIT:
			do_commit(m); /* a live upgrade in progress: the new master takes over */
			begin_stop(m, true);
			break;
		case SIGCHLD:
			reap(m);
			break;
		case SIGHUP:
			if (m->upgrade_pid > 0)
				do_rollback(m);
			else
				do_reload_checked(m, false);
			break;
		case SIGUSR2:
			do_upgrade(m);
			break;
		case SIGUSR1: { /* logrotate: reopen the access logs */
			const child *h = &m->kids[m->rt.nworkers];
			bst_logger_reopen(h->pid > 0 ? h->chan : -1);
			break;
		}
		case SIGWINCH:
			do_winch(m);
			break;
		default:
			bst_log(BST_LOG_WARN, "signal %d ignored", (int)si.ssi_signo);
			break;
		}
	}
}

/* ---- timers ---- */

static uint64_t earliest(uint64_t a, uint64_t b)
{
	return a == 0 ? b : b == 0 ? a : a < b ? a : b;
}

static uint64_t next_event(const master *m)
{
	uint64_t t = earliest(m->deadline, m->state == RUNNING ? m->startup_deadline : 0);
	t = earliest(t, m->sec_at);
	t = earliest(t, m->olds_deadline);
	t = earliest(t, m->quit_new_at);
	if (m->state == RUNNING)
		t = earliest(t, bst_acme_master_next());
	if (m->xdp != NULL) /* the 1 Hz stats poll; 0 means not polled yet: now */
		t = earliest(t, m->xdp_at != 0 ? m->xdp_at : 1);
	for (int i = 0; i < m->nkids; i++) {
		const child *c = &m->kids[i];
		t = earliest(t, c->respawn_at);
		t = earliest(t, c->kill_at);
		t = earliest(t, c->eof_at != 0 ? c->eof_at + BST_CHAN_EOF_GRACE_MS : 0);
	}
	return t;
}

static void stop_deadline(master *m)
{
	char name[32];
	bool graceful = m->state == STOP_GRACEFUL;
	for (int i = 0; i < m->nkids; i++) {
		child *c = &m->kids[i];
		if (c->pid <= 0)
			continue;
		unsigned long long conns = c->slot >= 0
			? atomic_load_explicit(&m->rt.stats[c->slot].conns, memory_order_relaxed) : 0;
		bst_log(BST_LOG_WARN, "%s reached: killing %s (pid %ld) with %llu connections",
			graceful ? "shutdown_timeout" : "fast stop timeout",
			child_name(c, name, sizeof name), (long)c->pid, conns);
		kill_child(c);
	}
	m->deadline = 0;
}

/* A slot crash looping from the start must not keep the server "starting" for ever: a later exit
 * 78 would end a server whose other slots are serving. */
static void startup_passed(master *m)
{
	char name[32];
	m->started = true;
	m->startup_deadline = 0;
	for (int i = 0; i < m->nkids; i++)
		if (!m->kids[i].ready)
			bst_log(BST_LOG_ERROR, "startup deadline passed: %s is not ready",
				child_name(&m->kids[i], name, sizeof name));
	drain_olds(m); /* a reload must not leave two generations for ever */
}

static void run_timers(master *m)
{
	char name[32];
	uint64_t now = now_ms();
	if (m->deadline != 0 && now >= m->deadline)
		stop_deadline(m);
	if (m->startup_deadline != 0 && now >= m->startup_deadline && m->state == RUNNING)
		startup_passed(m);
	if (m->olds_deadline != 0 && now >= m->olds_deadline) { /* shutdown_timeout for the old */
		m->olds_deadline = 0;
		for (size_t i = 0; i < m->nolds; i++)
			if (m->olds[i].pid > 0) {
				bst_log(BST_LOG_WARN, "reload: shutdown_timeout reached: killing old %s (pid %ld)",
					child_name(&m->olds[i], name, sizeof name), (long)m->olds[i].pid);
				kill_child(&m->olds[i]);
			}
	}
	if (m->quit_new_at != 0 && now >= m->quit_new_at) /* a rollback whose workers are late */
		quit_new(m);
	if (m->state == RUNNING)
		bst_acme_master_tick(&m->rt, now); /* `tls auto`: start the ACME job when due */
	if (m->sec_at != 0 && now >= m->sec_at) /* block requests of the workers */
		m->sec_at = bst_sec_master_tick(now);
	if (m->xdp != NULL && now >= m->xdp_at) { /* XDP counters, 1 Hz */
		bst_xdp_stats_poll(m->xdp);
		m->xdp_at = now + 1000;
	}
	for (int i = 0; i < m->nkids; i++) {
		child *c = &m->kids[i];
		if (c->respawn_at != 0 && now >= c->respawn_at) {
			c->respawn_at = 0;
			int rc = spawn(m, c);
			if (rc != 0) {
				bst_log(BST_LOG_ERROR, "%s: respawn: %s",
					child_name(c, name, sizeof name), strerror(-rc));
				c->respawn_at = now + BST_RESPAWN_BASE_MS;
			}
		}
		if (c->kill_at != 0 && now >= c->kill_at) {
			c->kill_at = 0;
			bst_log(BST_LOG_WARN, "%s (pid %ld) outlived its replacement deadline: killing it",
				child_name(c, name, sizeof name), (long)c->pid);
			kill_child(c);
		}
		if (c->eof_at != 0 && now >= c->eof_at + BST_CHAN_EOF_GRACE_MS) {
			c->eof_at = 0;
			if (c->pid > 0) {
				bst_log(BST_LOG_ERROR, "%s (pid %ld) closed its channel: killing it",
					child_name(c, name, sizeof name), (long)c->pid);
				kill_child(c);
			}
		}
	}
}

/* ---- the loop ---- */

static bool any_child(const master *m, int upto)
{
	for (int i = 0; i < upto; i++)
		if (m->kids[i].pid > 0)
			return true;
	return false;
}

static void run_loop(master *m)
{
	for (;;) {
		if (m->state != RUNNING) {
			bool olds = false;
			for (size_t i = 0; i < m->nolds; i++)
				olds |= m->olds[i].pid > 0;
			if (!any_child(m, m->nkids) && !olds)
				return;
			if (!m->helper_told && !any_child(m, m->rt.nworkers)) {
				m->helper_told = true;
				tell_stop(&m->kids[m->rt.nworkers], true);
			}
		}
		nfds_t n = 0;
		m->pfds[n++] = (struct pollfd){ .fd = m->sigfd, .events = POLLIN };
		for (int i = 0; i < m->nkids; i++)
			if (m->kids[i].chan >= 0) {
				m->poll_kid[n] = i;
				m->pfds[n++] = (struct pollfd){ .fd = m->kids[i].chan, .events = POLLIN };
			}
		uint64_t next = next_event(m), now = now_ms();
		int timeout = -1;
		if (next != 0)
			timeout = next <= now ? 0 : next - now > 60000 ? 60000 : (int)(next - now);
		int rc = poll(m->pfds, n, timeout);
		if (rc < 0 && errno != EINTR) {
			bst_log(BST_LOG_ERROR, "poll: %s", strerror(errno));
			begin_stop(m, false);
		}
		if (rc > 0) {
			/* Each entry names its child by index, so reads may close channels freely. */
			for (nfds_t k = 1; k < n; k++)
				if (m->pfds[k].revents != 0)
					read_channel(m, &m->kids[m->poll_kid[k]]);
			if (m->pfds[0].revents != 0)
				read_signals(m);
		}
		run_timers(m);
	}
}

static void teardown(master *m)
{
	/* The other master of a live upgrade shares the XDP pins and links and the ticket keys:
	 * they are its now (a committed upgrade) or still its (a rolled back new master). */
	bool shared = m->upgrade_pid > 0 || (m->upgrade_parent > 0 && getppid() == m->upgrade_parent);
	if (shared)
		bst_xdp_hand_over(m->xdp);
	close_listeners(m);
	bst_logger_teardown();
	bst_metrics_teardown();
	bst_admin_teardown();
	for (size_t i = 0; i < m->nreuseport; i++)
		bst_reuseport_free(m->reuseport[i]);
	free(m->reuseport);
	free(m->routes);
	bst_xdp_detach(m->xdp); /* as on_exit says (xdp/loader.h) */
	m->xdp = NULL;
	for (size_t i = 0; i < m->rt.nlisteners; i++)
		free(m->rt.listeners[i].fds);
	free(m->rt.listeners);
	for (int i = 0; m->kids != NULL && i < m->nkids; i++)
		close_chan(&m->kids[i]);
	for (size_t i = 0; i < m->nolds; i++)
		close_chan(&m->olds[i]);
	free(m->olds);
	free(m->kids);
	free(m->pfds);
	free(m->poll_kid);
	if (m->rt.ocsp != NULL)
		munmap(m->rt.ocsp, bst_ocsp_region_size());
	if (m->rt.early != NULL)
		munmap(m->rt.early, bst_early_size());
	if (m->rt.tickets != NULL) {
		if (!shared) /* the keys do not outlive the process, unless another master uses them */
			memset(m->rt.tickets, 0, bst_tickets_size());
		munmap(m->rt.tickets, bst_tickets_size());
	}
	if (m->rt.stats != NULL)
		munmap(m->rt.stats, m->stats_size);
	if (m->stats_fd >= 0)
		close(m->stats_fd);
	if (m->sigfd >= 0)
		close(m->sigfd);
	if (m->pid_fd >= 0) {
		if (bst_pidfile_is(m->pid_fd, m->pid_path)) /* renamed or replaced: not ours */
			unlink(m->pid_path);
		close(m->pid_fd);
	}
	bst_log_set_socket(false);
	bst_log_init(2, BST_LOG_WARN);
	if (m->rt.log_inherited >= 0)
		close(m->rt.log_inherited);
	if (m->rt.log_base_fd > 2)
		close(m->rt.log_base_fd);
	if (m->rt.pidns_fd >= 0)
		close(m->rt.pidns_fd);
#ifdef BST_TEST
	bst_test_master_leak();
#endif
}

static bool quic_configured(const bst_config *cfg)
{
	for (size_t i = 0; i < cfg->global.nservers; i++)
		for (size_t j = 0; j < cfg->global.servers[i]->nlistens; j++)
			if (cfg->global.servers[i]->listens[j].http3)
				return true;
	return false;
}

int bst_master_run(bst_config *cfg)
{
	master m;
	memset(&m, 0, sizeof m);
	m.rt.cfg = cfg;
	m.rt.master_pid = getpid();
	m.rt.log_base_fd = m.rt.log_inherited = m.rt.channel = m.rt.pidns_fd = -1;
	m.sigfd = m.pid_fd = m.stats_fd = -1;
	bst_err e = {.msg = ""};

	bst_io_ignore_sigpipe();
	bst_log_set_tag("master");
	if (open_logs(&m, &e) != 0) {
		fprintf(stderr, "bastion: %s\n", e.msg);
		return 1;
	}
	bst_crash_install();
	const bst_inherit *inh = bst_inherit_load(); /* before any shared memory: it may be inherited */
	if (inh->refused) { /* a live upgrade from a binary of another state format */
		bst_err_set(&e, "upgrade: refusing the handed-over state: %s", inh->why);
		startup_error(&m, &e);
		teardown(&m);
		return BST_EXIT_STATE;
	}
	m.upgrade_parent = inh->upgrade_parent;
	adopt_olds(&m, inh);
	m.rt.nworkers = cfg->global.workers_auto ? (int)bst_io_cpu_count() : cfg->global.workers;
	m.rt.ncpu = bst_listener_ncpu();
	/* The counters move to the kept `metrics` region first, so every registration below lands
	 * there (and finds the previous image's entries after a reload or upgrade). */
	if (bst_metrics_setup(cfg, &e) != 0)
		goto fail;
	if (bst_admin_setup(cfg, &e) != 0) /* `admin {}`: the mailbox and the Unix socket */
		goto fail;
	if (bst_acme_setup(cfg, &e) != 0) /* `tls auto`: the challenge table workers answer from */
		goto fail;
	bst_huge_pages_apply(cfg); /* before any fork: every child inherits the allocator setting */
	/* Registered here, before any fork: the counters table has one registering writer. */
	bst_io_backend_init();
	bst_tls_conn_init();
	bst_h2_guard_init();
	bst_quic_init();
	bst_tls_ktls_init();
	if (bst_tls_ktls_check(cfg, &e) != 0)
		goto fail;
	{
		uint64_t rot;
		unsigned keep;
		const char *file;
		bool tickets = bst_tickets_policy(cfg, &rot, &keep, &file), quic = quic_configured(cfg);
		if (tickets || quic) {
			bool kept; /* after a reload: the same keys, so resumption keeps working */
			m.rt.tickets = bst_shm_create_kept("bastion-tickets", bst_tickets_size(), &kept);
			if (m.rt.tickets == NULL) {
				bst_err_set(&e, "ticket keys shared memory: %s", strerror(errno));
				goto fail;
			}
			/* A keys file is read again; generated keys are kept, and rotate on schedule. A
			 * region kept for QUIC alone holds no key: tickets turned on by this reload get
			 * a fresh one. */
			bst_ticket_key probe[1];
			bool have = kept && bst_tickets_snapshot(m.rt.tickets, probe, 1) > 0;
			memset(probe, 0, sizeof probe);
			if (tickets && (!have || file != NULL) &&
			    bst_tickets_init(m.rt.tickets, keep, file, &e) != 0)
				goto fail;
			if (quic && (kept ? bst_tickets_quic_adopt(m.rt.tickets)
					  : bst_tickets_quic_init(m.rt.tickets)) != 0) {
				bst_err_set(&e, "quic: no randomness for the token secrets");
				goto fail;
			}
			if (bst_tickets_protect(m.rt.tickets) != 0)
				bst_log(BST_LOG_WARN, "tls: cannot lock the ticket keys in memory (RLIMIT_MEMLOCK): "
						      "they may reach swap");
			if (tickets)
				bst_tickets_use(m.rt.tickets);
		}
	}
	if (bst_early_wanted(cfg)) {
		m.rt.early = bst_shm_create("bastion-early", bst_early_size(), NULL);
		if (m.rt.early == NULL) {
			bst_err_set(&e, "early data shared memory: %s", strerror(errno));
			goto fail;
		}
		bst_early_use(m.rt.early);
	}
	if (bst_ocsp_wanted(cfg)) {
		m.rt.ocsp = bst_shm_create("bastion-ocsp", bst_ocsp_region_size(), NULL);
		if (m.rt.ocsp == NULL) {
			bst_err_set(&e, "OCSP shared memory: %s", strerror(errno));
			goto fail;
		}
		if (bst_ocsp_setup(cfg, m.rt.ocsp, &e) != 0)
			goto fail;
	}
	if (bst_upstate_setup(cfg, &e) != 0) /* upstream addresses and health, shared */
		goto fail;
	if (bst_sec_setup(cfg, m.rt.nworkers, &e) != 0) /* limits, blocks, challenge: shared */
		goto fail;
	if (bst_logger_setup(cfg, m.rt.nworkers, &e) != 0) /* access log files and rings */
		goto fail;
	m.crash_ctr = bst_counter_register("bastion_child_crashes_total",
					   "children that died unasked", NULL);
	m.sigfd = bst_signals_master();
	if (m.sigfd < 0) {
		bst_err_set(&e, "signalfd: %s", strerror(errno));
		goto fail;
	}
	if (bst_master_resolve_user_(&m, &e) != 0 || bst_master_open_pid_file_(&m, &e) != 0 || bst_roots_open(m.rt.cfg, &e) != 0 ||
	    bst_cache_setup(m.rt.cfg, m.rt.nworkers, m.rt.drop_uid || m.rt.drop_gid, m.rt.uid, m.rt.gid, &e) != 0 || bst_master_probe_backend_(&m, &e) != 0 ||
	    bst_master_decide_sqpoll_(&m, &e) != 0 || bst_ns_setup(&m.rt, &e) != 0 || bst_master_create_listeners_(&m, &e) != 0 || bst_master_setup_xdp_(&m, &e) != 0 ||
	    bst_master_map_status_(&m, &e) != 0)
		goto fail;

	m.nkids = m.rt.nworkers + 1;
	m.kids = calloc((size_t)m.nkids, sizeof *m.kids);
	m.pfds = calloc((size_t)m.nkids + 1, sizeof *m.pfds);
	m.poll_kid = calloc((size_t)m.nkids + 1, sizeof *m.poll_kid);
	if (m.kids == NULL || m.pfds == NULL || m.poll_kid == NULL) {
		bst_err_set(&e, "out of memory");
		goto fail;
	}
	for (int i = 0; i < m.nkids; i++) {
		m.kids[i].slot = i < m.rt.nworkers ? i : -1;
		m.kids[i].chan = -1;
	}
	uint64_t window = BST_STARTUP_DEADLINE_MS;
#ifdef BST_TEST
	window = bst_test_startup_deadline(window);
#endif
	m.startup_deadline = now_ms() + window;
	m.sec_at = bst_sec_master_tick(now_ms());
	for (int i = m.nkids - 1; i >= 0; i--) { /* the helper first */
		int rc = spawn(&m, &m.kids[i]);
		if (rc != 0) {
			bst_err_set(&e, "fork: %s", strerror(-rc));
			startup_error(&m, &e);
			m.failed = true;
			begin_stop(&m, false);
			break;
		}
	}
	run_loop(&m);
	int status = m.failed ? 1 : 0;
	bst_log(BST_LOG_INFO, "exiting");
	teardown(&m);
	return status;
fail:
	startup_error(&m, &e);
	teardown(&m);
	return 1;
}

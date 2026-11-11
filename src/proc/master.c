/* See master.h. */
#include "proc/master.h"

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
#include "tls/conn.h"
#include "tls/ktls.h"
#include "tls/ocsp.h"
#include "tls/tickets.h"

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
	if (m->announced || m->state != RUNNING)
		return;
	for (int i = 0; i < m->nkids; i++) /* the helper counts: its startup can fail too */
		if (!m->kids[i].ready)
			return;
	m->started = m->announced = true;
	m->startup_deadline = 0;
	bst_log(BST_LOG_INFO, "ready: %d workers on %s", rt->nworkers, bst_backend_name(rt->backend));
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
	c->eof_at = c->kill_at = 0;
	if (m->state != RUNNING) {
		bst_log(BST_LOG_INFO, "%s (pid %ld) exited", name, (long)pid);
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
			begin_stop(m, true);
			break;
		case SIGCHLD:
			reap(m);
			break;
		default: /* HUP, USR2 */
			bst_log(BST_LOG_WARN, "signal %d ignored: reload and upgrade arrive in Phase 14",
				(int)si.ssi_signo);
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
}

static void run_timers(master *m)
{
	char name[32];
	uint64_t now = now_ms();
	if (m->deadline != 0 && now >= m->deadline)
		stop_deadline(m);
	if (m->startup_deadline != 0 && now >= m->startup_deadline && m->state == RUNNING)
		startup_passed(m);
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
			if (!any_child(m, m->nkids))
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
	close_listeners(m);
	for (size_t i = 0; i < m->rt.nlisteners; i++)
		free(m->rt.listeners[i].fds);
	free(m->rt.listeners);
	for (int i = 0; m->kids != NULL && i < m->nkids; i++)
		close_chan(&m->kids[i]);
	free(m->kids);
	free(m->pfds);
	free(m->poll_kid);
	if (m->rt.ocsp != NULL)
		munmap(m->rt.ocsp, bst_ocsp_region_size());
	if (m->rt.tickets != NULL) {
		memset(m->rt.tickets, 0, bst_tickets_size()); /* the keys do not outlive the process */
		munmap(m->rt.tickets, bst_tickets_size());
	}
	if (m->rt.stats != NULL)
		munmap(m->rt.stats, m->stats_size);
	if (m->stats_fd >= 0)
		close(m->stats_fd);
	if (m->sigfd >= 0)
		close(m->sigfd);
	if (m->pid_fd >= 0) {
		unlink(m->rt.cfg->global.pid);
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
	m.rt.nworkers = cfg->global.workers_auto ? (int)bst_io_cpu_count() : cfg->global.workers;
	m.rt.ncpu = bst_listener_ncpu();
	/* Registered here, before any fork: the counters table has one registering writer. */
	bst_io_backend_init();
	bst_tls_conn_init();
	bst_tls_ktls_init();
	if (bst_tls_ktls_check(cfg, &e) != 0)
		goto fail;
	{
		uint64_t rot;
		unsigned keep;
		const char *file;
		if (bst_tickets_policy(cfg, &rot, &keep, &file)) {
			m.rt.tickets = bst_shm_create("bastion-tickets", bst_tickets_size(), NULL);
			if (m.rt.tickets == NULL) {
				bst_err_set(&e, "ticket keys shared memory: %s", strerror(errno));
				goto fail;
			}
			if (bst_tickets_init(m.rt.tickets, keep, file, &e) != 0)
				goto fail;
			if (bst_tickets_protect(m.rt.tickets) != 0)
				bst_log(BST_LOG_WARN, "tls: cannot lock the ticket keys in memory (RLIMIT_MEMLOCK): "
						      "they may reach swap");
			bst_tickets_use(m.rt.tickets);
		}
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
	m.crash_ctr = bst_counter_register("bastion_child_crashes_total",
					   "children that died unasked", NULL);
	m.sigfd = bst_signals_master();
	if (m.sigfd < 0) {
		bst_err_set(&e, "signalfd: %s", strerror(errno));
		goto fail;
	}
	if (bst_master_resolve_user_(&m, &e) != 0 || bst_master_open_pid_file_(&m, &e) != 0 || bst_roots_open(m.rt.cfg, &e) != 0 || bst_master_probe_backend_(&m, &e) != 0 ||
	    bst_master_decide_sqpoll_(&m, &e) != 0 || bst_ns_setup(&m.rt, &e) != 0 || bst_master_create_listeners_(&m, &e) != 0 || bst_master_map_status_(&m, &e) != 0)
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

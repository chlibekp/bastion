/* See worker.h. Start order matters, and runtime.h and architecture section 8 say why. */
#include "proc/worker.h"
#include "handlers/ofcache.h"

#include "core/log.h"
#include "core/wheel.h"
#include "io/admission.h"
#include "io/backend.h"
#include "io/listener.h"
#include "io/net.h"
#include "io/sock.h"
#include "proc/channel.h"
#include "proc/test_hooks.h"
#include "route/regex.h"

#include "http/h1/conn.h"
#include "http/h3/quic.h"
#include "route/vhost.h"

#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

bst_worker_conn_fn bst_worker_on_conn;
void (*bst_worker_on_drain)(bst_worker *w);

typedef struct accept_ctx {
	bst_worker *w;
	const bst_cfg_listen *cfg;
	int fd;
	bst_timer retry;
	bool paused;  /* accept failed: waiting out limits.accept_backoff, and no sweep meanwhile */
	bool logged;  /* that pause is already in the log */
	bst_quic_endpoint *quic; /* an `http3` listener: its UDP endpoint, nothing to accept */
} accept_ctx;

struct bst_worker {
	bst_runtime *rt;
	int slot;
	bst_loop *loop;
	bst_sock *chan;
	bst_admission adm;
	accept_ctx *acc;
	bst_timer stop_timer, sweep_timer;
	unsigned sweep_ms;
	unsigned long long conns;
	size_t listening; /* listeners not yet quiet, while stopping */
	bool stopping;
	bool draining; /* listeners are gone: the last connection ends the process */
	bool chan_dead; /* test seam: the channel was shut down on purpose */
	bst_ofcache *ofc; /* open_file_cache: NULL when off */
};

bst_ofcache *bst_worker_ofcache(bst_worker *w)
{
	return w->ofc;
}

bst_loop *bst_worker_loop(bst_worker *w)
{
	return w->loop;
}

int bst_worker_slot(const bst_worker *w)
{
	return w->slot;
}

void bst_worker_conn_opened(bst_worker *w)
{
	w->conns++;
	atomic_store_explicit(&w->rt->stats[w->slot].conns, w->conns, memory_order_relaxed);
}

void bst_worker_conn_closed(bst_worker *w)
{
	w->conns--;
	atomic_store_explicit(&w->rt->stats[w->slot].conns, w->conns, memory_order_relaxed);
	if (w->draining && w->conns == 0)
		bst_loop_stop(w->loop);
}

const bst_config *bst_worker_config(const bst_worker *w)
{
	return w->rt->cfg;
}

const bst_cfg_limits *bst_worker_limits(const bst_worker *w)
{
	return w->adm.lim;
}

bool bst_admit_conn(bst_worker *w)
{
	return bst_adm_admit(&w->adm, w->conns);
}

bool bst_worker_mem_charge(bst_worker *w, size_t n)
{
	return bst_adm_mem_charge(&w->adm, n);
}

void bst_worker_mem_release(bst_worker *w, size_t n)
{
	bst_adm_mem_release(&w->adm, n);
}

bool bst_overloaded(const bst_worker *w)
{
	return bst_adm_overloaded(&w->adm);
}

void bst_worker_refused(bst_worker *w)
{
	bst_adm_refused(&w->adm);
}

int bst_worker_cpu(int slot, bool pin, int ncpu)
{
	return pin && ncpu > 0 ? slot % ncpu : -1;
}

static void pin_to_cpu(const bst_runtime *rt, int slot)
{
	int cpu = bst_worker_cpu(slot, rt->pin_workers, rt->ncpu);
	if (cpu < 0)
		return;
	cpu_set_t set;
	CPU_ZERO(&set);
	if (cpu < CPU_SETSIZE)
		CPU_SET((size_t)cpu, &set);
	if (cpu >= CPU_SETSIZE || sched_setaffinity(0, sizeof set, &set) != 0)
		bst_log(BST_LOG_WARN, "cannot pin to CPU %d: %s; incoming_cpu steering will not match",
			cpu, strerror(errno));
}

static void set_nofile(const bst_runtime *rt)
{
	unsigned n = rt->cfg->global.worker_rlimit_nofile;
	if (n == 0)
		return;
	struct rlimit lim = { n, n };
	if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
		bst_log(BST_LOG_WARN, "worker_rlimit_nofile %u: %s", n, strerror(errno));
}

/* ---- accepting ---- */

static void accept_retry(void *ud);
static void listener_quiet(accept_ctx *a);

static void on_accept(void *ud, int fd, const bst_sockaddr *peer, int err)
{
	accept_ctx *a = ud;
	bst_worker *w = a->w;
	if (err == -ECANCELED) { /* the end of bst_io_accept_quiesce */
		listener_quiet(a);
		return;
	}
	if (err < 0) { /* the backend paused this listener: see bst_accept_cb */
		unsigned ms = w->adm.lim->accept_backoff_ms;
		a->paused = true;
		if (err == -EMFILE || err == -ENFILE)
			(void)bst_adm_shed_fds(&w->adm, a->fd); /* clients get a reset, not a wait */
		if (!a->logged)
			bst_log(BST_LOG_WARN, "accept: %s; paused, retrying every %u ms",
				strerror(-err), ms);
		a->logged = true;
		if (!w->stopping)
			bst_loop_timer_arm(w->loop, &a->retry, ms, accept_retry, a);
		return;
	}
	if (a->logged) {
		a->logged = false;
		bst_log(BST_LOG_INFO, "accept: resumed");
	}
	if (!bst_admit_conn(w)) { /* over max_connections: counted, and closed at once */
		close(fd);
		return;
	}
	(void)bst_sock_apply_accepted(fd, a->cfg->tcp);
	if (bst_worker_on_conn != NULL)
		bst_worker_on_conn(w, fd, peer, a->cfg);
	else
		close(fd);
}

static void accept_retry(void *ud)
{
	accept_ctx *a = ud;
	if (a->w->stopping)
		return;
	a->paused = false;
	(void)bst_io_accept_stop(a->w->loop, a->fd);
	int rc = bst_io_accept_start(a->w->loop, a->fd, on_accept, a);
	if (rc != 0) {
		bst_log(BST_LOG_ERROR, "accept restart: %s", strerror(-rc));
		_exit(1);
	}
}

/* io_uring only. Multishot accept waits on the listener as an exclusive waiter, and a dead
 * process's ring is torn down by a kernel work item that can run after its parent has reaped it.
 * For that moment two waiters sit on the socket and a new connection can wake the dead one,
 * which leaves the connection queued with the replacement asleep until the next one arrives. So
 * a worker also looks at its queues itself: soon and often right after start, when that can
 * happen, then rarely, which costs an accept4 per listener per second. Phase 14's new generations
 * take over live sockets the same way, so this stays on for the worker's life. */
static void accept_sweep(void *ud)
{
	bst_worker *w = ud;
	if (w->stopping)
		return;
	for (size_t i = 0; i < w->rt->nlisteners; i++)
		if (!w->acc[i].paused && w->acc[i].quic == NULL) /* a paused listener waits out its backoff */
			(void)bst_io_accept_drain(w->acc[i].fd, on_accept, &w->acc[i],
						  BST_ACCEPT_DRAIN_MAX);
	w->sweep_ms = w->sweep_ms * 2 < BST_ACCEPT_SWEEP_MAX_MS ? w->sweep_ms * 2
								: BST_ACCEPT_SWEEP_MAX_MS;
	bst_loop_timer_arm(w->loop, &w->sweep_timer, w->sweep_ms, accept_sweep, w);
}

/* A listener's accepts have all been delivered: forget it, take what the kernel has already
 * completed on its queue, and close it, so a graceful stop does not reset those. A connection
 * arriving after the close is refused or reset by the kernel: that is what stopping means. */
static void listener_quiet(accept_ctx *a)
{
	bst_worker *w = a->w;
	if (a->quic != NULL) {
		/* The socket stays open: the CONNECTION_CLOSE packets are queued on it, HTTP/3
		 * connections finish their requests after GOAWAY over it, and the process exit closes
		 * it. */
		bst_quic_endpoint_drain(a->quic);
	} else {
		(void)bst_io_accept_stop(w->loop, a->fd);
		(void)bst_io_accept_drain(a->fd, on_accept, a, BST_ACCEPT_DRAIN_MAX);
		close(a->fd);
		w->rt->listeners[a - w->acc].fds[w->slot] = -1;
	}
	if (--w->listening == 0) {
		w->draining = true;
		if (bst_worker_on_drain != NULL)
			bst_worker_on_drain(w);
		if (w->conns == 0)
			bst_loop_stop(w->loop);
	}
}

/* On a timer, not from the STOP message: accept completions of the same batch come first. */
static void stop_accepting(void *ud)
{
	bst_worker *w = ud;
	bst_timer_cancel(&w->sweep_timer);
	w->listening = w->rt->nlisteners;
	for (size_t i = 0; i < w->rt->nlisteners; i++) {
		accept_ctx *a = &w->acc[i];
		bst_timer_cancel(&a->retry);
		/* 1: on_accept hears -ECANCELED once the in-flight accepts are through. */
		if (a->quic != NULL || bst_io_accept_quiesce(w->loop, a->fd) != 1)
			listener_quiet(a);
	}
}

/* ---- the channel ---- */

static void on_message(bst_worker *w, const bst_msg *m)
{
	if (m->type != BST_MSG_STOP)
		return; /* master does not send anything else */
	if (!m->stop.graceful)
		_exit(0);
#ifdef BST_TEST
	bst_test_channel_on_stop(w->slot, w->rt->channel);
#endif
	if (w->stopping)
		return;
	w->stopping = true;
	bst_loop_timer_arm(w->loop, &w->stop_timer, 1, stop_accepting, w);
}

static void on_channel(void *ud, uint32_t events, int err)
{
	bst_worker *w = ud;
	(void)events, (void)err;
	for (;;) {
		bst_msg m;
		int rc = bst_chan_recv(w->rt->channel, &m);
		if (rc == -EAGAIN)
			break;
		if (rc == 1) {
			on_message(w, &m);
			continue;
		}
		if (rc == -EPROTO)
			continue;
		if (w->chan_dead)
			return;
#ifdef BST_TEST
		if (rc == 0 && bst_test_ignore_channel_eof())
			return;
#endif
		bst_log(BST_LOG_WARN, "master is gone: exiting");
		_exit(0);
	}
	if (bst_io_poll(w->chan, POLLIN | POLLRDHUP, on_channel, w) != 0)
		_exit(1);
}

/* The `http3` listeners' endpoints, before the sandbox: bst_udp_start sets socket options the
 * filter refuses afterwards. Each reads the QUIC figures of its listener's default server. */
static void start_quic(bst_worker *w)
{
	bst_runtime *rt = w->rt;
	w->acc = calloc(rt->nlisteners ? rt->nlisteners : 1, sizeof *w->acc);
	if (w->acc == NULL) {
		bst_log(BST_LOG_ERROR, "out of memory");
		_exit(BST_EXIT_STARTUP);
	}
	for (size_t i = 0; i < rt->nlisteners; i++) {
		accept_ctx *a = &w->acc[i];
		a->w = w;
		a->cfg = rt->listeners[i].cfg;
		a->fd = rt->listeners[i].fds[w->slot];
		bst_timer_init(&a->retry);
		if (!a->cfg->http3)
			continue;
		bst_listener_set *set = bst_vhost_set_new(rt->cfg, a->cfg);
		const bst_cfg_server *dflt = set != NULL ? bst_vhost_default(set) : NULL;
		bst_sock *s = bst_sock_wrap(w->loop, a->fd);
		bst_err e = {.msg = ""};
		/* The set lives as long as the worker: every HTTP/3 request looks its server up in it. */
		if (dflt == NULL || s == NULL ||
		    (a->quic = bst_quic_endpoint_start(w, s, set, &dflt->common.http.quic, &e)) == NULL) {
			bst_log(BST_LOG_ERROR, "http3 listener: %s", e.msg[0] ? e.msg : "out of memory");
			_exit(BST_EXIT_STARTUP);
		}
	}
}

static void start_accepting(bst_worker *w)
{
	bst_runtime *rt = w->rt;
	for (size_t i = 0; i < rt->nlisteners; i++) {
		accept_ctx *a = &w->acc[i];
		if (a->quic != NULL)
			continue;
		int rc = bst_io_accept_start(w->loop, a->fd, on_accept, a);
		if (rc != 0) {
			bst_log(BST_LOG_ERROR, "accept start: %s", strerror(-rc));
			_exit(BST_EXIT_STARTUP);
		}
	}
}

void bst_worker_main(int slot, bst_runtime *rt)
{
	static bst_worker w;
	char tag[32];
	snprintf(tag, sizeof tag, "worker/%d", slot);
	w.rt = rt;
	w.slot = slot;
	bst_timer_init(&w.stop_timer);
	bst_timer_init(&w.sweep_timer);

	bst_child_start(rt, slot, tag);
#ifdef BST_TEST
	bst_test_child_exit78();
	bst_test_sandbox_claim(slot);
#endif
	pin_to_cpu(rt, slot);
	set_nofile(rt);
	w.loop = bst_child_loop_and_drop(rt, slot, tag);
	bst_regex_set_limits(rt->cfg->global.regex_match_limit, rt->cfg->global.regex_depth_limit);
	if (rt->cfg->global.ofc_max > 0)
		w.ofc = bst_ofcache_new(rt->cfg->global.ofc_max, rt->cfg->global.ofc_ttl_ms,
					rt->cfg->global.ofc_errors);
	bst_adm_init(&w.adm, &rt->cfg->global.limits, w.loop, STDIN_FILENO);
	bst_child_watch_master(rt);
#ifdef BST_TEST
	bst_test_child_report(w.loop); /* it probes a tty and opens files: outside the filter */
	bst_test_sandbox_prepare(w.loop);
#endif
	start_quic(&w);
	bst_child_sandbox(rt, BST_SANDBOX_WORKER);
	bst_io_backend_report(w.loop);
	bst_worker_on_conn = bst_h1_on_conn;
	bst_worker_on_drain = bst_h1_drain;
#ifdef BST_TEST
	bst_test_child_crash(slot);
	bst_test_raw_install();
	bst_test_child_aio_crash(slot, w.loop);
	bst_test_sandbox_probe_ring();
#endif
	w.chan = bst_sock_wrap(w.loop, rt->channel);
	if (w.chan == NULL || bst_io_poll(w.chan, POLLIN | POLLRDHUP, on_channel, &w) != 0) {
		bst_log(BST_LOG_ERROR, "channel: no socket");
		_exit(BST_EXIT_STARTUP);
	}
	start_accepting(&w);
	if (bst_loop_backend(w.loop) == BST_BACKEND_URING) {
		w.sweep_ms = BST_ACCEPT_SWEEP_MS;
		bst_loop_timer_arm(w.loop, &w.sweep_timer, w.sweep_ms, accept_sweep, &w);
	}
	bst_msg ready = {.type = BST_MSG_READY, .ready = {.backend = bst_loop_backend(w.loop)}};
	if (bst_chan_send(rt->channel, &ready) != 0)
		_exit(1);
#ifdef BST_TEST
	w.chan_dead = bst_test_channel_garbage(slot, rt->channel);
	bst_test_sandbox_probe();
#endif
	int rc = bst_loop_run(w.loop);
	if (rc < 0)
		bst_log(BST_LOG_ERROR, "worker loop failed: %s", strerror(-rc));
	/* No teardown: the kernel closes every socket and ring, and a sanitizer's exit check cannot
	 * run in a sandboxed child anyway. Sends that completed are in the kernel already. */
	_exit(rc < 0 ? 1 : 0);
}

#include "io/loop.h"

#include "core/log.h"
#include "io/loop_priv.h"
#include "io/udp_priv.h"
#include "io/uring_priv.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

uint64_t bst_mono_ms_(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

uint64_t bst_loop_now_ms(const bst_loop *l)
{
	(void)l;
	return bst_mono_ms_();
}

/* io_uring is "not here" (fall back under auto) when ring creation says ENOSYS, EPERM (a
 * seccomp filter, kernel.io_uring_disabled) or EINVAL for every flag set, or when the probe
 * finds a required opcode or feature missing. Decided by stage and errno, nothing else:
 * EPERM from a restriction hook or any later step is a real error. */
static bool uring_unavailable(int rc, bst_open_stage stage)
{
	if (stage == BST_OPEN_SETUP)
		return rc == -ENOSYS || rc == -EPERM || rc == -EINVAL;
	return stage == BST_OPEN_PROBE && rc == -EOPNOTSUPP;
}

/* The cause of an unavailable io_uring, for the log line and the startup error. */
static void unavailable_reason(int rc, bst_open_stage stage, const bst_err *e, char *out,
			       size_t cap)
{
	if (stage == BST_OPEN_SETUP && rc == -ENOSYS) {
		snprintf(out, cap, "io_uring_setup failed with ENOSYS (this kernel has no io_uring)");
	} else if (stage == BST_OPEN_SETUP && rc == -EINVAL) {
		snprintf(out, cap, "io_uring_setup refused every flag set (EINVAL)");
	} else if (stage == BST_OPEN_SETUP) {
		int dis = -1;
		FILE *f = fopen("/proc/sys/kernel/io_uring_disabled", "r");
		if (f != NULL) {
			if (fscanf(f, "%d", &dis) != 1)
				dis = -1;
			fclose(f);
		}
		if (dis > 0)
			snprintf(out, cap, "io_uring_setup failed with EPERM (kernel.io_uring_disabled=%d)",
				 dis);
		else
			snprintf(out, cap, "io_uring_setup failed with EPERM (blocked by seccomp or a "
					   "security policy)");
	} else {
		snprintf(out, cap, "%s", e->msg + (strncmp(e->msg, "io_uring: ", 10) == 0 ? 10 : 0));
	}
}

const char *bst_loop_backend_reason(const bst_loop *l)
{
	return l->reason;
}

#ifdef BST_TEST
unsigned bst_test_dead_left; /* sockets still waiting after the last bst_loop_free's flush */
#endif

bst_loop *bst_loop_new(const bst_loop_cfg *cfg, bst_err *err)
{
	bst_backend want = cfg != NULL ? cfg->backend : BST_BACKEND_AUTO;
	bool napi_req = cfg != NULL && cfg->uring_napi != 0 && cfg->uring_napi_require;
	const bst_loop_ops *ops = want == BST_BACKEND_EPOLL ? &bst_loop_epoll_ops
							    : &bst_loop_uring_ops;
	bst_loop *l = calloc(1, sizeof *l);
	if (l == NULL) {
		bst_err_set(err, "out of memory");
		return NULL;
	}
	l->ops = ops;
	bst_wheel_init(&l->wheel, bst_mono_ms_());
	atomic_init(&l->stop, false);
	l->socks = bst_slab_new(sizeof(bst_sock), 256);
	if (l->socks == NULL) {
		bst_err_set(err, "out of memory");
		free(l);
		return NULL;
	}
	bst_err uerr = {.msg = ""};
	bst_open_stage stage = BST_OPEN_OTHER;
	int orc = ops->open(l, cfg, ops == &bst_loop_uring_ops ? &uerr : err, &stage);
	if (ops == &bst_loop_uring_ops && orc != 0) {
		char why[160];
		if (want == BST_BACKEND_AUTO && uring_unavailable(orc, stage)) {
			unavailable_reason(orc, stage, &uerr, why, sizeof why);
			if (napi_req) {
				bst_err_set(err, "uring_napi is required but io_uring is unavailable "
						 "(%s), so epoll would run without NAPI", why);
				orc = -1;
			} else {
				snprintf(l->reason, sizeof l->reason, "%s", why);
				ops = &bst_loop_epoll_ops;
				l->ops = ops;
				orc = ops->open(l, cfg, err, &stage);
			}
		} else {
			if (want == BST_BACKEND_URING && uring_unavailable(orc, stage)) {
				unavailable_reason(orc, stage, &uerr, why, sizeof why);
				bst_err_set(err, "backend uring is not available: %s", why);
			} else {
				bst_err_set(err, "%s", uerr.msg);
			}
			orc = -1;
		}
	} else if (ops == &bst_loop_epoll_ops) {
		if (napi_req) {
			bst_err_set(err, "uring_napi is required but backend epoll has no NAPI busy "
					 "polling");
			if (orc == 0)
				ops->close(l);
			orc = -1;
		} else {
			snprintf(l->reason, sizeof l->reason, "backend epoll configured");
		}
	}
	if (orc != 0) {
		bst_slab_free(l->socks);
		free(l);
		return NULL;
	}
	if (ops == &bst_loop_uring_ops)
		bst_uring_describe_(l, l->reason, sizeof l->reason);
	/* Threads start here, before any sandbox exists. */
	l->aio = bst_aio_new_(l, cfg, err);
	if (l->aio == NULL) {
		ops->close(l);
		bst_slab_free(l->socks);
		free(l);
		return NULL;
	}
	return l;
}

static void free_sock(bst_loop *l, bst_sock *s)
{
	bst_udp_free_(s);
	if (s->fd_held)
		close(s->fd);
	bst_slab_put(l->socks, s);
}

/* Free closed sockets with nothing in flight; the rest stay until released. */
static void flush_dead(bst_loop *l)
{
	bst_sock *keep = NULL;
	while (l->dead != NULL) {
		bst_sock *s = l->dead;
		l->dead = s->dnext;
		if (s->inflight > 0) {
			s->dnext = keep;
			keep = s;
		} else {
			free_sock(l, s);
		}
	}
	l->dead = keep;
}

void bst_loop_free(bst_loop *l)
{
	if (l == NULL)
		return;
	bst_aio_free_(l->aio); /* drains the pool and runs the remaining done callbacks */
	l->aio = NULL;
	if (l->ops->drain != NULL)
		l->ops->drain(l);
	flush_dead(l);
#ifdef BST_TEST
	bst_test_dead_left = 0;
	for (bst_sock *d = l->dead; d != NULL; d = d->dnext)
		bst_test_dead_left++;
#endif
	/* Only a failed drain leaves sockets here. Nothing will dispatch for them again (the
	 * backend is closed below), so their memory can go; their fds are closed. */
	for (bst_sock *s = l->dead; s != NULL; s = s->dnext)
		if (s->fd_held)
			close(s->fd);
	bst_net_loop_free_(l);
	l->ops->close(l);
	bst_slab_free(l->socks);
	free(l);
}

bst_backend bst_loop_backend(const bst_loop *l)
{
	return l->ops->id;
}

void bst_loop_stop(bst_loop *l)
{
	atomic_store(&l->stop, true);
	l->ops->wake(l);
}

void bst_loop_wake(bst_loop *l)
{
	l->ops->wake(l);
}

void bst_loop_set_wake_cb(bst_loop *l, void (*cb)(void *), void *ud)
{
	l->wake_cb = cb;
	l->wake_ud = ud;
}

void bst_loop_woken_(bst_loop *l)
{
	if (l->aio != NULL)
		bst_aio_drain_(l->aio);
	if (l->wake_cb != NULL)
		l->wake_cb(l->wake_ud);
}

void bst_loop_timer_arm(bst_loop *l, bst_timer *t, uint64_t ms, void (*cb)(void *), void *ud)
{
	/* The wheel's clock only moves when the loop advances it, which can lag real time (a
	 * long callback, or arming before run). Add the lag so the deadline is ms from now,
	 * and one more ms because now is truncated: the timer is never early. */
	uint64_t now = bst_mono_ms_();
	uint64_t lag = now > l->wheel.now ? now - l->wheel.now : 0;
	if (ms == 0)
		ms = 1;
	ms = ms > UINT64_MAX - lag - 1 ? UINT64_MAX : ms + lag + 1;
	bst_timer_arm(&l->wheel, t, ms, cb, ud);
}

/* Sleep bound for epoll_wait: next_ms can exceed INT_MAX (the wheel spans 2^32 ms). */
static int wait_timeout(bst_loop *l)
{
	int64_t next = bst_wheel_next_ms(&l->wheel);
	if (next < 0)
		return -1;
	/* next is measured from the wheel's time, but dispatch and flush have used real
	 * time since the last advance. */
	uint64_t now = bst_mono_ms_();
	uint64_t spent = now > l->wheel.now ? now - l->wheel.now : 0;
	next = (uint64_t)next > spent ? next - (int64_t)spent : 0;
	return next > INT_MAX ? INT_MAX : (int)next;
}

int bst_loop_run(bst_loop *l)
{
	int rc = 0;
	while (!atomic_load(&l->stop)) {
		int n = l->ops->wait(l, wait_timeout(l));
		if (n < 0) {
			bst_log(BST_LOG_ERROR, "event loop wait failed: %s", strerror(-n));
			rc = n;
			break;
		}
		/* Advance before I/O callbacks so their timeouts start from a fresh now. Never
		 * from a callback. */
		bst_wheel_advance(&l->wheel, bst_mono_ms_());
		if (n > 0)
			l->ops->dispatch(l, n);
		flush_dead(l);
	}
	atomic_store(&l->stop, false);
	return rc;
}

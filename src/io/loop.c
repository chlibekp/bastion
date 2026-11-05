#include "io/loop.h"

#include "core/log.h"
#include "io/loop_priv.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

bst_loop *bst_loop_new(const bst_loop_cfg *cfg, bst_err *err)
{
	bst_backend want = cfg != NULL ? cfg->backend : BST_BACKEND_AUTO;
	const bst_loop_ops *ops;
	if (want == BST_BACKEND_AUTO || want == BST_BACKEND_EPOLL) {
		ops = &bst_loop_epoll_ops;
	} else {
		bst_err_set(err, "io_uring backend is not available in this build");
		return NULL;
	}
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
	if (ops->open(l, err) != 0) {
		bst_slab_free(l->socks);
		free(l);
		return NULL;
	}
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
			bst_slab_put(l->socks, s);
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
	flush_dead(l);
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

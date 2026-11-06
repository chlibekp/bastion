#include "core/log.h"
#include "io/loop.h"
#include "io/loop_priv.h"
#include "io/sock.h"
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Backend-parametrised: BST_TEST_BACKEND selects it (epoll or uring, default epoll). */
static int backend_selected(bst_backend *out)
{
	const char *b = getenv("BST_TEST_BACKEND");
	if (b == NULL || strcmp(b, "epoll") == 0) {
		*out = BST_BACKEND_EPOLL;
		return 1;
	}
	if (strcmp(b, "uring") == 0) {
		*out = BST_BACKEND_URING;
		return 1;
	}
	printf("# SKIP: unknown backend '%s'\n", b);
	return 0;
}

#define LOOP_OR_SKIP(l, cfg_)                                                           \
	bst_loop_cfg cfg_ = {0};                                                        \
	if (!backend_selected(&cfg_.backend))                                           \
		return;                                                                 \
	bst_err err_;                                                                   \
	bst_loop *l = bst_loop_new(&cfg_, &err_);                                       \
	ASSERT(l != NULL)

static uint64_t mono_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* ---- timers ---- */

typedef struct {
	bst_loop *l;
	uint64_t fired_at;
	int fired;
} tprobe;

static void on_timer(void *ud)
{
	tprobe *p = ud;
	p->fired++;
	p->fired_at = bst_loop_now_ms(p->l);
	bst_loop_stop(p->l);
}

TEST(timer_fires)
{
	LOOP_OR_SKIP(l, cfg);
	tprobe p = {.l = l};
	bst_timer t;
	bst_timer_init(&t);
	uint64_t t0 = bst_loop_now_ms(l);
	bst_loop_timer_arm(l, &t, 10, on_timer, &p);
	ASSERT_EQ(bst_loop_run(l), 0);
	ASSERT_EQ(p.fired, 1);
	/* No earlier than the deadline. The upper bound is 25 ms, not 10: sanitizer builds in
	 * Docker cannot hold 10 ms reliably. */
	ASSERT(p.fired_at >= t0 + 10);
	ASSERT(p.fired_at <= t0 + 10 + 25);
	bst_loop_free(l);
}

TEST(timer_init_clears_garbage)
{
	LOOP_OR_SKIP(l, cfg);
	bst_timer t;
	memset(&t, 0xA5, sizeof t);
	bst_timer_init(&t);
	tprobe p = {.l = l};
	bst_loop_timer_arm(l, &t, 1, on_timer, &p);
	ASSERT_EQ(bst_loop_run(l), 0);
	ASSERT_EQ(p.fired, 1);
	bst_loop_free(l);
}

/* ---- poll ---- */

typedef struct {
	bst_loop *l;
	bst_sock *s;
	int calls;
	uint32_t events;
	int err;
	int rearm;     /* re-arm from the callback */
	int write_fd;  /* if >= 0, write a byte here from the callback before re-arming */
} pprobe;

static void on_poll(void *ud, uint32_t events, int err)
{
	pprobe *p = ud;
	p->calls++;
	p->events = events;
	p->err = err;
	if (p->write_fd >= 0)
		(void)!write(p->write_fd, "y", 1);
	if (p->rearm > 0) {
		p->rearm--;
		ASSERT_EQ(bst_io_poll(p->s, POLLIN, on_poll, p), 0);
	}
}

static void on_stop_timer(void *ud)
{
	bst_loop_stop(ud);
}

static void run_for(bst_loop *l, uint64_t ms)
{
	bst_timer t;
	bst_timer_init(&t);
	bst_loop_timer_arm(l, &t, ms, on_stop_timer, l);
	(void)bst_loop_run(l);
	bst_timer_cancel(&t);
}

static void on_poll_stop(void *ud, uint32_t events, int err)
{
	pprobe *p = ud;
	p->calls++;
	p->events = events;
	p->err = err;
	bst_loop_stop(p->l);
}

TEST(poll_ready)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	ASSERT(s != NULL);
	pprobe p = {.l = l, .s = s, .write_fd = -1};
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_poll_stop, &p), 0);
	ASSERT_EQ(write(sv[1], "x", 1), 1);
	ASSERT_EQ(bst_loop_run(l), 0);
	ASSERT_EQ(p.calls, 1);
	ASSERT(p.events & POLLIN);
	ASSERT_EQ(p.err, 0);
	bst_sock_close(s);
	close(sv[1]);
	bst_loop_free(l);
}

TEST(close_cancels)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	ASSERT(s != NULL);
	pprobe p = {.l = l, .s = s, .write_fd = -1};
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_poll, &p), 0);
	ASSERT_EQ(write(sv[1], "x", 1), 1);
	bst_sock_close(s);
	run_for(l, 30);
	ASSERT_EQ(p.calls, 0);
	close(sv[1]);
	bst_loop_free(l);
}

typedef struct {
	bst_loop *l;
	bst_sock *self, *other;
	int *calls;
	bst_sock **survivor;
} xprobe;

static void on_poll_close_other(void *ud, uint32_t events, int err)
{
	(void)events;
	(void)err;
	xprobe *p = ud;
	(*p->calls)++;
	*p->survivor = p->self;
	bst_sock_close(p->other);
	bst_loop_stop(p->l);
}

TEST(close_in_same_batch)
{
	LOOP_OR_SKIP(l, cfg);
	int a[2], b[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, a), 0);
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, b), 0);
	bst_sock *sa = bst_sock_wrap(l, a[0]);
	bst_sock *sb = bst_sock_wrap(l, b[0]);
	ASSERT(sa != NULL && sb != NULL);
	int calls = 0;
	bst_sock *survivor = NULL;
	xprobe pa = {l, sa, sb, &calls, &survivor}, pb = {l, sb, sa, &calls, &survivor};
	ASSERT_EQ(bst_io_poll(sa, POLLIN, on_poll_close_other, &pa), 0);
	ASSERT_EQ(bst_io_poll(sb, POLLIN, on_poll_close_other, &pb), 0);
	/* Both ready before the loop runs, so one epoll_wait returns both. Whichever runs
	 * first closes the other, whose callback must then never run. */
	ASSERT_EQ(write(a[1], "x", 1), 1);
	ASSERT_EQ(write(b[1], "x", 1), 1);
	run_for(l, 50);
	ASSERT_EQ(calls, 1);
	ASSERT(survivor == sa || survivor == sb);
	bst_sock_close(survivor); /* the other was closed by its peer's callback */
	close(a[1]);
	close(b[1]);
	bst_loop_free(l);
}

TEST(poll_oneshot_and_rearm)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	ASSERT(s != NULL);
	/* First callback leaves its byte unread, writes another and re-arms: the readiness
	 * that exists at re-arm time must be delivered, not lost under edge-triggering. The
	 * second callback does not re-arm. */
	pprobe p = {.l = l, .s = s, .rearm = 1, .write_fd = sv[1]};
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_poll, &p), 0);
	ASSERT_EQ(write(sv[1], "x", 1), 1);
	run_for(l, 40);
	/* 2 deliveries: the second callback wrote again but did not re-arm. */
	ASSERT_EQ(p.calls, 2);
	/* Not re-armed: more data must not be delivered. */
	p.write_fd = -1;
	ASSERT_EQ(write(sv[1], "z", 1), 1);
	run_for(l, 40);
	ASSERT_EQ(p.calls, 2);
	/* Arming again picks up the pending data. */
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_poll_stop, &p), 0);
	ASSERT_EQ(bst_loop_run(l), 0);
	ASSERT_EQ(p.calls, 3);
	bst_sock_close(s);
	close(sv[1]);
	bst_loop_free(l);
}

/* ---- wake and stop ---- */

static atomic_int woke;

static void on_wake(void *ud)
{
	atomic_fetch_add(&woke, 1);
	bst_loop_stop(ud);
}

static void *waker(void *arg)
{
	struct timespec ts = {0, 20 * 1000000};
	nanosleep(&ts, NULL);
	bst_loop_wake(arg);
	return NULL;
}

TEST(wake_from_thread)
{
	bst_loop_cfg cfg = {0};
	if (!backend_selected(&cfg.backend))
		return;
	bst_err err;
	bst_loop *l = bst_loop_new(&cfg, &err);
	ASSERT(l != NULL);
	bst_loop_set_wake_cb(l, on_wake, l);
	atomic_store(&woke, 0);
	tprobe watchdog_p = {.l = l};
	bst_timer watchdog;
	bst_timer_init(&watchdog);
	bst_loop_timer_arm(l, &watchdog, 5000, on_timer, &watchdog_p);
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, waker, l), 0);
	uint64_t t0 = mono_ms();
	ASSERT_EQ(bst_loop_run(l), 0);
	uint64_t dt = mono_ms() - t0;
	pthread_join(th, NULL);
	ASSERT_EQ(atomic_load(&woke), 1);
	ASSERT_EQ(watchdog_p.fired, 0); /* returned because of the wake, not the 5 s timer */
	ASSERT(dt < 1000);
	bst_loop_free(l);
}

TEST(wake_coalesces_and_pre_run_wake_is_kept)
{
	LOOP_OR_SKIP(l, cfg);
	bst_loop_set_wake_cb(l, on_wake, l);
	atomic_store(&woke, 0);
	for (int i = 0; i < 100; i++)
		bst_loop_wake(l);
	ASSERT_EQ(bst_loop_run(l), 0);
	ASSERT_EQ(atomic_load(&woke), 1);
	bst_loop_free(l);
}

TEST(stop_inside_callback)
{
	LOOP_OR_SKIP(l, cfg);
	int a[2], b[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, a), 0);
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, b), 0);
	bst_sock *sa = bst_sock_wrap(l, a[0]);
	bst_sock *sb = bst_sock_wrap(l, b[0]);
	ASSERT(sa != NULL && sb != NULL);
	pprobe pa = {.l = l, .s = sa, .write_fd = -1}, pb = {.l = l, .s = sb, .write_fd = -1};
	ASSERT_EQ(bst_io_poll(sa, POLLIN, on_poll_stop, &pa), 0);
	ASSERT_EQ(bst_io_poll(sb, POLLIN, on_poll_stop, &pb), 0);
	ASSERT_EQ(write(a[1], "x", 1), 1);
	ASSERT_EQ(write(b[1], "x", 1), 1);
	ASSERT_EQ(bst_loop_run(l), 0);
	/* Stop was called by the first callback; the rest of the batch still ran. */
	ASSERT_EQ(pa.calls + pb.calls, 2);
	bst_sock_close(sa);
	bst_sock_close(sb);
	close(a[1]);
	close(b[1]);
	bst_loop_free(l);
}

TEST(backend_reported)
{
	LOOP_OR_SKIP(l, cfg);
	ASSERT_EQ(bst_loop_backend(l), cfg.backend);
	bst_loop_free(l);
}

/* ---- fix round 1 ---- */

static void busy(uint64_t ms)
{
	uint64_t end = mono_ms() + ms;
	while (mono_ms() < end)
		;
}

static int fake_calls;
static void on_count(void *ud, uint32_t ev, int err)
{
	(void)ud;
	(void)ev;
	(void)err;
	fake_calls++;
}

/* fd number reuse while a stale event for the old socket is in the same batch */
typedef struct {
	bst_loop *l;
	bst_sock *self, *other, **fresh, **survivor;
	int *calls, *reused, *peer;
} rprobe;

static int fresh_calls;
static void on_fresh(void *ud, uint32_t ev, int err)
{
	(void)ud;
	(void)ev;
	(void)err;
	fresh_calls++;
}

static void on_reuse(void *ud, uint32_t ev, int err)
{
	(void)ev;
	(void)err;
	rprobe *p = ud;
	(*p->calls)++;
	*p->survivor = p->self;
	int oldfd = p->other->fd;
	bst_sock_close(p->other);
	int nv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, nv) != 0)
		abort();
	*p->reused = nv[0] == oldfd;
	*p->fresh = bst_sock_wrap(p->l, nv[0]);
	*p->peer = nv[1];
	if (bst_io_poll(*p->fresh, POLLIN, on_fresh, NULL) != 0)
		abort();
}

TEST(fd_reuse_same_batch)
{
	LOOP_OR_SKIP(l, cfg);
	int a[2], x[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, a), 0);
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, x), 0);
	bst_sock *sa = bst_sock_wrap(l, a[0]), *sx = bst_sock_wrap(l, x[0]);
	int calls = 0, reused = 0, peer = -1;
	bst_sock *fresh = NULL, *surv = NULL;
	rprobe pa = {l, sa, sx, &fresh, &surv, &calls, &reused, &peer};
	rprobe px = {l, sx, sa, &fresh, &surv, &calls, &reused, &peer};
	ASSERT_EQ(bst_io_poll(sa, POLLIN, on_reuse, &pa), 0);
	ASSERT_EQ(bst_io_poll(sx, POLLIN, on_reuse, &px), 0);
	ASSERT_EQ(write(a[1], "x", 1), 1);
	ASSERT_EQ(write(x[1], "x", 1), 1);
	fresh_calls = 0;
	run_for(l, 30);
	ASSERT_EQ(calls, 1);
	ASSERT_EQ(reused, 1);
	ASSERT_EQ(fresh_calls, 0); /* the stale event must not reach the new socket */
	ASSERT_EQ(write(peer, "y", 1), 1);
	run_for(l, 30);
	ASSERT_EQ(fresh_calls, 1);
	bst_sock_close(fresh);
	bst_sock_close(surv);
	close(peer);
	close(a[1]);
	close(x[1]);
	bst_loop_free(l);
}

/* A dup of the fd keeps the open file description alive after close(), so only an
 * explicit EPOLL_CTL_DEL (io_uring: a cancel) stops events for a closed socket. */
TEST(close_with_dup_fd_alive)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	int d = dup(sv[0]);
	ASSERT(d >= 0);
	bst_sock *s = bst_sock_wrap(l, d);
	fake_calls = 0;
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_count, NULL), 0);
	bst_sock_close(s);
	run_for(l, 5);
	int o[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, o), 0);
	bst_sock *s2 = bst_sock_wrap(l, o[0]);
	ASSERT(s2 != NULL);
	ASSERT_EQ(bst_io_poll(s2, POLLIN, on_count, NULL), 0);
	ASSERT_EQ(write(sv[1], "x", 1), 1);
	run_for(l, 20);
	ASSERT_EQ(fake_calls, 0);
	bst_sock_close(s2);
	close(o[1]);
	close(sv[0]);
	close(sv[1]);
	bst_loop_free(l);
}

static int self_calls;
static void on_self(void *ud, uint32_t ev, int err)
{
	(void)ev;
	(void)err;
	self_calls++;
	bst_sock *s = *(bst_sock **)ud;
	bst_sock_close(s);
	bst_sock_close(s); /* same iteration: no-op */
}

TEST(self_close_and_double_close)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	self_calls = 0;
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_self, &s), 0);
	ASSERT_EQ(write(sv[1], "x", 1), 1);
	run_for(l, 20);
	ASSERT_EQ(self_calls, 1);
	close(sv[1]);
	bst_loop_free(l);
}

/* The wheel advances before I/O dispatch: a due timer closes a socket whose event is
 * already in the batch. */
static void on_close_timer(void *ud)
{
	bst_sock_close(ud);
}

TEST(wheel_advances_before_dispatch)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	fake_calls = 0;
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_count, NULL), 0);
	bst_timer t;
	bst_timer_init(&t);
	bst_loop_timer_arm(l, &t, 2, on_close_timer, s);
	ASSERT_EQ(write(sv[1], "x", 1), 1);
	busy(10); /* timer due and I/O ready before the first wait */
	run_for(l, 20);
	ASSERT_EQ(fake_calls, 0);
	close(sv[1]);
	bst_loop_free(l);
}

/* Timer armed from a slow callback: the wait must account for time already spent. */
static uint64_t late_arm, late_fire, late_cb_end;
static bst_timer late_t;
static void on_late_timer(void *ud)
{
	late_fire = mono_ms();
	bst_loop_stop(ud);
}
static void on_slow(void *ud, uint32_t ev, int err)
{
	(void)ev;
	(void)err;
	late_arm = mono_ms();
	bst_loop_timer_arm(ud, &late_t, 10, on_late_timer, ud);
	busy(40);
	late_cb_end = mono_ms();
}

TEST(timer_after_slow_callback)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	bst_timer_init(&late_t);
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_slow, l), 0);
	ASSERT_EQ(write(sv[1], "x", 1), 1);
	ASSERT_EQ(bst_loop_run(l), 0);
	ASSERT(late_fire >= late_arm + 10); /* never early */
	uint64_t ideal = late_arm + 10 > late_cb_end ? late_arm + 10 : late_cb_end;
	/* The timer was due while the callback still ran, so it is ideally due the moment
	 * the callback returns. Allow a few ms for sanitizer builds. */
	ASSERT(late_fire - ideal <= 5);
	bst_sock_close(s);
	close(sv[1]);
	bst_loop_free(l);
}

static uint64_t mono_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

/* Armed long after loop_new, before run: the wheel's clock is stale, and the deadline
 * must still be ms from the arm call. */
TEST(timer_armed_after_idle_gap)
{
	LOOP_OR_SKIP(l, cfg);
	busy(30);
	tprobe p = {.l = l};
	bst_timer t;
	bst_timer_init(&t);
	uint64_t t0 = mono_ns();
	bst_loop_timer_arm(l, &t, 10, on_timer, &p);
	ASSERT_EQ(bst_loop_run(l), 0);
	ASSERT(mono_ns() - t0 >= 10000000u);
	bst_loop_free(l);
}

/* A timer is never early, measured in nanoseconds (ms truncation must not hide it). */
TEST(timer_never_early_many)
{
	LOOP_OR_SKIP(l, cfg);
	for (int i = 0; i < 20; i++) {
		tprobe p = {.l = l};
		bst_timer t;
		bst_timer_init(&t);
		uint64_t t0 = mono_ns();
		bst_loop_timer_arm(l, &t, 3, on_timer, &p);
		ASSERT_EQ(bst_loop_run(l), 0);
		ASSERT(mono_ns() - t0 >= 3000000u);
		struct timespec ts = {0, (long)(i * 53000 + 17)};
		nanosleep(&ts, NULL); /* vary the sub-millisecond phase */
	}
	bst_loop_free(l);
}

/* Replacing a poll while its old event is in the same batch. */
typedef struct {
	bst_sock *other;
	int *first;
	uint32_t *ev2;
	int *c2;
} qprobe;
static qprobe q2;
static void on_q2(void *ud, uint32_t ev, int err)
{
	(void)err;
	qprobe *p = ud;
	(*p->c2)++;
	*p->ev2 = ev;
}
static void on_q(void *ud, uint32_t ev, int err)
{
	(void)ev;
	(void)err;
	qprobe *p = ud;
	if (*p->first)
		return;
	*p->first = 1;
	q2 = *p;
	if (bst_io_poll(p->other, POLLOUT, on_q2, &q2) != 0)
		abort();
}

TEST(replace_poll_same_batch)
{
	LOOP_OR_SKIP(l, cfg);
	int a[2], b[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, a), 0);
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, b), 0);
	bst_sock *sa = bst_sock_wrap(l, a[0]), *sb = bst_sock_wrap(l, b[0]);
	int first = 0, c2 = 0;
	uint32_t ev2 = 0;
	qprobe pa = {sb, &first, &ev2, &c2}, pb = {sa, &first, &ev2, &c2};
	ASSERT_EQ(bst_io_poll(sa, POLLIN, on_q, &pa), 0);
	ASSERT_EQ(bst_io_poll(sb, POLLIN, on_q, &pb), 0);
	ASSERT_EQ(write(a[1], "x", 1), 1);
	ASSERT_EQ(write(b[1], "x", 1), 1);
	run_for(l, 30);
	/* The stale POLLIN must not reach the POLLOUT callback, and the real POLLOUT that
	 * the re-arm produces must not be lost. */
	ASSERT_EQ(c2, 1);
	ASSERT(ev2 & POLLOUT);
	ASSERT(!(ev2 & POLLIN));
	bst_sock_close(sa);
	bst_sock_close(sb);
	close(a[1]);
	close(b[1]);
	bst_loop_free(l);
}

TEST(poll_generation_advances)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	uint32_t g0 = s->gen;
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_count, NULL), 0);
	ASSERT(s->gen != g0);
	ASSERT_EQ(s->want, POLLIN);
	uint32_t g1 = s->gen;
	ASSERT_EQ(bst_io_poll(s, POLLOUT, on_count, NULL), 0);
	ASSERT(s->gen != g1);
	bst_sock_close(s);
	close(sv[1]);
	bst_loop_free(l);
}

/* Fake backend that keeps a closed socket in flight (as io_uring does until the
 * cancellation completes), possibly across iterations. */
static const bst_loop_ops *real_ops;
static void held_detach(bst_sock *s)
{
	real_ops->sock_detach(s);
	s->inflight++;
}

TEST(inflight_defers_free_until_release)
{
	LOOP_OR_SKIP(l, cfg);
	bst_loop_ops fake = *l->ops;
	real_ops = l->ops;
	fake.sock_detach = held_detach;
	l->ops = &fake;
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	fake_calls = 0;
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_count, NULL), 0);
	ASSERT_EQ(write(sv[1], "x", 1), 1);
	bst_sock_close(s);
	for (int i = 0; i < 3; i++)
		run_for(l, 3); /* several iterations while the cancel is still outstanding */
	ASSERT_EQ(fake_calls, 0);
	int o[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, o), 0);
	bst_sock *s2 = bst_sock_wrap(l, o[0]);
	ASSERT(s2 != NULL);
	ASSERT(s2 != s); /* not reused while in flight */
	bst_sock_release_(s);
	run_for(l, 3);
	bst_sock *s3 = bst_sock_wrap(l, dup(o[1]));
	ASSERT(s3 == s); /* freed once released */
	ASSERT_EQ(fake_calls, 0);
	l->ops = real_ops;
	bst_sock_close(s2);
	bst_sock_close(s3);
	close(o[1]);
	close(sv[1]);
	bst_loop_free(l);
}

/* flush_dead runs on every iteration, not only at loop_free. */
TEST(dead_socks_freed_each_iteration)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	bst_sock_close(s);
	run_for(l, 2);
	int o[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, o), 0);
	bst_sock *s2 = bst_sock_wrap(l, o[0]);
	ASSERT(s2 == s);
	bst_sock_close(s2);
	close(sv[1]);
	close(o[1]);
	bst_loop_free(l);
}

/* Fault injection through a copied ops table. */
static int seen_timeout;
static int fake_wait_fail(bst_loop *l, int timeout_ms)
{
	(void)l;
	seen_timeout = timeout_ms;
	return -EIO;
}

TEST(fatal_wait_and_int_max_clamp)
{
	LOOP_OR_SKIP(l, cfg);
	bst_loop_ops ops = *l->ops;
	const bst_loop_ops *orig = l->ops;
	ops.wait = fake_wait_fail;
	l->ops = &ops;
	bst_timer t;
	bst_timer_init(&t);
	bst_loop_timer_arm(l, &t, (UINT64_C(1) << 32) - 5, on_stop_timer, l); /* ~49.7 days */
	seen_timeout = 0;
	int lp[2];
	ASSERT_EQ(pipe2(lp, O_NONBLOCK), 0);
	bst_log_init(lp[1], BST_LOG_ERROR); /* capture the logged reason; keep output clean */
	int rc = bst_loop_run(l);
	bst_log_init(STDERR_FILENO, BST_LOG_WARN);
	char logbuf[256] = {0};
	ASSERT(read(lp[0], logbuf, sizeof logbuf - 1) > 0);
	close(lp[0]);
	close(lp[1]);
	ASSERT(strstr(logbuf, "wait failed") != NULL);
	ASSERT_EQ(rc, -EIO); /* fatal error: negative return, no spin */
	ASSERT_EQ(seen_timeout, INT_MAX);
	bst_timer_cancel(&t);
	l->ops = orig;
	bst_loop_free(l);
}

static int wait_count;
static int counting_wait(bst_loop *l, int timeout_ms)
{
	wait_count++;
	return real_ops->wait(l, timeout_ms);
}

TEST(idle_wait_does_not_spin)
{
	LOOP_OR_SKIP(l, cfg);
	bst_loop_ops ops = *l->ops;
	real_ops = l->ops;
	ops.wait = counting_wait;
	l->ops = &ops;
	wait_count = 0;
	run_for(l, 40);
	ASSERT(wait_count <= 8);
	l->ops = real_ops;
	bst_loop_free(l);
}

/* EINTR is retried (here, a signal handler that also wakes the loop). */
static bst_loop *sig_loop;
static void on_sig(int sig)
{
	(void)sig;
	bst_loop_wake(sig_loop);
}
static atomic_int sig_woke;
static void on_sig_wake(void *ud)
{
	atomic_fetch_add(&sig_woke, 1);
	bst_loop_stop(ud);
}
static void *kicker(void *arg)
{
	struct timespec ts = {0, 20 * 1000000};
	nanosleep(&ts, NULL);
	pthread_kill(*(pthread_t *)arg, SIGUSR1);
	return NULL;
}

TEST(wake_from_signal_handler)
{
	LOOP_OR_SKIP(l, cfg);
	sig_loop = l;
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_sig; /* no SA_RESTART: epoll_wait returns EINTR */
	ASSERT_EQ(sigaction(SIGUSR1, &sa, NULL), 0);
	bst_loop_set_wake_cb(l, on_sig_wake, l);
	atomic_store(&sig_woke, 0);
	bst_timer wd;
	bst_timer_init(&wd);
	bst_loop_timer_arm(l, &wd, 3000, on_stop_timer, l);
	pthread_t me = pthread_self(), th;
	ASSERT_EQ(pthread_create(&th, NULL, kicker, &me), 0);
	uint64_t t0 = mono_ms();
	ASSERT_EQ(bst_loop_run(l), 0);
	pthread_join(th, NULL);
	ASSERT_EQ(atomic_load(&sig_woke), 1);
	ASSERT(mono_ms() - t0 < 1000);
	bst_timer_cancel(&wd);
	signal(SIGUSR1, SIG_DFL);
	bst_loop_free(l);
}

/* A stop before run returns at once, without running a batch. */
TEST(stop_before_run_runs_no_batch)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	fake_calls = 0;
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_count, NULL), 0);
	ASSERT_EQ(write(sv[1], "x", 1), 1);
	bst_loop_stop(l);
	ASSERT_EQ(bst_loop_run(l), 0);
	ASSERT_EQ(fake_calls, 0);
	bst_sock_close(s);
	close(sv[1]);
	bst_loop_free(l);
}

/* POLLOUT, POLLHUP and SO_ERROR delivery. */
static uint32_t got_ev;
static int got_err, got_n;
static void on_ev(void *ud, uint32_t ev, int err)
{
	got_ev = ev;
	got_err = err;
	got_n++;
	bst_loop_stop(ud);
}

TEST(pollout_delivered)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	got_n = 0;
	ASSERT_EQ(bst_io_poll(s, POLLOUT, on_ev, l), 0);
	ASSERT_EQ(bst_loop_run(l), 0);
	ASSERT_EQ(got_n, 1);
	ASSERT(got_ev & POLLOUT);
	bst_sock_close(s);
	close(sv[1]);
	bst_loop_free(l);
}

TEST(pollhup_delivered)
{
	LOOP_OR_SKIP(l, cfg);
	int sv[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *s = bst_sock_wrap(l, sv[0]);
	got_n = 0;
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_ev, l), 0);
	close(sv[1]);
	ASSERT_EQ(bst_loop_run(l), 0);
	ASSERT_EQ(got_n, 1);
	ASSERT(got_ev & POLLHUP);
	ASSERT_EQ(got_err, 0);
	bst_sock_close(s);
	bst_loop_free(l);
}

TEST(pollerr_reports_so_error)
{
	LOOP_OR_SKIP(l, cfg);
	/* Find a loopback port nobody listens on, then connect to it. */
	int lf = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ASSERT_EQ(bind(lf, (struct sockaddr *)&a, sizeof a), 0);
	socklen_t al = sizeof a;
	ASSERT_EQ(getsockname(lf, (struct sockaddr *)&a, &al), 0);
	close(lf);
	int c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	int rc = connect(c, (struct sockaddr *)&a, sizeof a);
	ASSERT(rc == 0 || errno == EINPROGRESS || errno == ECONNREFUSED);
	bst_sock *s = bst_sock_wrap(l, c);
	got_n = 0;
	ASSERT_EQ(bst_io_poll(s, POLLOUT, on_ev, l), 0);
	ASSERT_EQ(bst_loop_run(l), 0);
	ASSERT_EQ(got_n, 1);
	ASSERT(got_ev & POLLERR);
	ASSERT_EQ(got_err, -ECONNREFUSED); /* negative errno, like every I/O callback */
	bst_sock_close(s);
	bst_loop_free(l);
}

TAP_MAIN()

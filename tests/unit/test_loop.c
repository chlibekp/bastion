#include "io/loop.h"
#include "io/sock.h"
#include "tap.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Backend-parametrised: BST_TEST_BACKEND selects it (default epoll). */
static int backend_selected(bst_backend *out)
{
	const char *b = getenv("BST_TEST_BACKEND");
	if (b == NULL || strcmp(b, "epoll") == 0) {
		*out = BST_BACKEND_EPOLL;
		return 1;
	}
	printf("# SKIP: backend '%s' is not built yet\n", b);
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
	ASSERT_EQ(bst_loop_backend(l), BST_BACKEND_EPOLL);
	bst_loop_free(l);
}

TAP_MAIN()

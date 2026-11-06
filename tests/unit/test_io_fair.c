/* Fairness and isolation between sockets of one loop, on both backends
 * (BST_TEST_BACKEND=epoll|uring): a caller holding recv buffers never stalls another
 * socket, a bulk sender does not starve a quiet one, and a closed socket's send never
 * reaches the connection that reuses its fd number. */
#include "uring_util.h"

#include <stdatomic.h>

static bst_backend backend(void)
{
	const char *b = getenv("BST_TEST_BACKEND");
	return b != NULL && strcmp(b, "uring") == 0 ? BST_BACKEND_URING : BST_BACKEND_EPOLL;
}

static bst_loop *mk(bst_loop_cfg cfg)
{
	cfg.backend = backend();
	bst_err e;
	bst_loop *l = bst_loop_new(&cfg, &e);
	if (l == NULL)
		printf("# bst_loop_new: %s\n", e.msg);
	return l;
}

static uint64_t now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

/* ---- holders ---- */

typedef struct {
	bst_buf *held;
	size_t got;
	int eof, err;
} holder;

static void on_hold(void *ud, bst_buf *d, int err)
{
	holder *h = ud;
	if (d == NULL) {
		if (err == 0)
			h->eof = 1;
		else
			h->err = err;
		return;
	}
	h->got += d->len;
	if (h->held == NULL)
		h->held = d; /* a slow client's partial request, kept by the caller */
	else
		bst_buf_unref(d);
}

#define NHOLD 40 /* more holders than the 16 ring buffers below */

TEST(holders_never_stall_others)
{
	/* 16 provided buffers on io_uring (epoll ignores it): 40 sockets each keep one buffer
	 * of a 4 KiB partial request, above the small-copy size. */
	bst_loop *l = mk((bst_loop_cfg){.uring_bufs = 16});
	ASSERT(l != NULL);
	static int ha[NHOLD], hb[NHOLD];
	static holder hs[NHOLD];
	static bst_sock *hsock[NHOLD];
	memset(hs, 0, sizeof hs);
	static unsigned char req[4096];
	memset(req, 'G', sizeof req);
	for (int i = 0; i < NHOLD; i++) {
		ASSERT_EQ(tcp_pair(&ha[i], &hb[i]), 0);
		hsock[i] = bst_sock_wrap(l, ha[i]);
		ASSERT_EQ(bst_io_recv_start(hsock[i], on_hold, &hs[i]), 0);
		ASSERT_EQ(write(hb[i], req, sizeof req), (ssize_t)sizeof req);
	}
	run_for(l, 100);
	int holding = 0;
	for (int i = 0; i < NHOLD; i++)
		holding += hs[i].held != NULL;
	ASSERT_EQ(holding, NHOLD); /* every holder got its data although few buffers exist */
	int va, vb;
	ASSERT_EQ(tcp_pair(&va, &vb), 0);
	bst_sock *vs = bst_sock_wrap(l, va);
	holder v = {0};
	ASSERT_EQ(bst_io_recv_start(vs, on_hold, &v), 0);
	ASSERT_EQ(write(vb, "GET / HTTP/1.1\r\n\r\n", 18), 18);
	uint64_t t0 = mono_ms();
	while (v.got == 0 && mono_ms() - t0 < 1000)
		run_for(l, 5);
	ASSERT_EQ(v.got, 18); /* served at once, not after the holders let go */
	close(vb);
	t0 = mono_ms();
	while (!v.eof && mono_ms() - t0 < 1000)
		run_for(l, 5);
	ASSERT_EQ(v.eof, 1); /* and its peer's EOF is seen */
	for (int i = 0; i < NHOLD; i++) {
		bst_buf_unref(hs[i].held);
		bst_sock_close(hsock[i]);
		close(hb[i]);
	}
	bst_buf_unref(v.held);
	bst_sock_close(vs);
	run_for(l, 5);
	bst_loop_free(l);
}

/* ---- a bulk sender next to a quiet socket ---- */

typedef struct {
	int fd;
	atomic_int stop;
} blaster;

static void *blast(void *p)
{
	blaster *b = p;
	static unsigned char buf[1 << 16];
	while (!atomic_load(&b->stop)) {
		ssize_t n = write(b->fd, buf, sizeof buf);
		if (n <= 0)
			break;
	}
	return NULL;
}

typedef struct {
	uint64_t sent_at, maxlat, sumlat;
	int n;
} lat;

static void on_count_drop(void *ud, bst_buf *d, int err)
{
	(void)err;
	if (d != NULL) {
		*(size_t *)ud += d->len;
		bst_buf_unref(d);
	}
}

static void on_lat(void *ud, bst_buf *d, int err)
{
	lat *x = ud;
	(void)err;
	if (d == NULL)
		return;
	uint64_t t = now_us() - x->sent_at;
	if (t > x->maxlat)
		x->maxlat = t;
	x->sumlat += t;
	x->n++;
	bst_buf_unref(d);
}

static struct {
	lat *x;
	int fd, rounds;
	bst_timer t;
	bst_loop *l;
} pinger;

static void ping(void *ud)
{
	(void)ud;
	if (pinger.rounds-- <= 0)
		return;
	pinger.x->sent_at = now_us();
	(void)!write(pinger.fd, "p", 1);
	bst_loop_timer_arm(pinger.l, &pinger.t, 2, ping, NULL);
}

TEST(bulk_sender_leaves_quiet_socket_responsive)
{
	bst_loop *l = mk((bst_loop_cfg){0});
	ASSERT(l != NULL);
	int ha, hb, va, vb;
	ASSERT_EQ(tcp_pair(&ha, &hb), 0);
	ASSERT_EQ(tcp_pair(&va, &vb), 0);
	int big = 8 << 20;
	setsockopt(ha, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
	bst_sock *hs = bst_sock_wrap(l, ha), *vs = bst_sock_wrap(l, va);
	size_t bulk = 0;
	lat x = {0};
	ASSERT_EQ(bst_io_recv_start(hs, on_count_drop, &bulk), 0);
	ASSERT_EQ(bst_io_recv_start(vs, on_lat, &x), 0);
	blaster bl = {.fd = hb};
	atomic_init(&bl.stop, 0);
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, blast, &bl), 0);
	pinger.x = &x;
	pinger.fd = vb;
	pinger.l = l;
	pinger.rounds = 1 << 30; /* the run ends on replies, not on a count of pings */
	bst_timer_init(&pinger.t);
	bst_test_uring_nobufs = 0;
	bst_loop_timer_arm(l, &pinger.t, 2, ping, NULL);
	/* Run until the quiet socket has had 300 replies or a generous deadline: a fixed 1 s
	 * window made the count depend on how much CPU the machine gave the 2 ms timer. */
	uint64_t deadline = mono_ms() + 60000;
	while (x.n < 300 && mono_ms() < deadline)
		run_for(l, 50);
	atomic_store(&bl.stop, 1);
	bst_timer_cancel(&pinger.t);
	bst_sock_close(hs);
	/* On io_uring the close only reaches the peer when the loop runs again, and a write
	 * blocked on a zero window is not woken by another thread's close(2): shut the blaster's
	 * socket down so its write fails, join, and only then close the fd. */
	shutdown(hb, SHUT_RDWR);
	pthread_join(th, NULL);
	close(hb);
	printf("# backend=%s bulk=%zu MiB pings=%d avg=%llu us max=%llu us nobufs=%u\n",
	       backend() == BST_BACKEND_URING ? "uring" : "epoll", bulk >> 20, x.n,
	       x.n ? (unsigned long long)(x.sumlat / (uint64_t)x.n) : 0ull,
	       (unsigned long long)x.maxlat, bst_test_uring_nobufs);
	ASSERT(bulk > (16u << 20)); /* the bulk stream really ran */
	ASSERT(x.n >= 300);          /* the quiet socket kept being served */
	ASSERT(x.maxlat < 100000);   /* loose for sanitizer builds in CI: 100 ms */
	/* The bulk stream may not drain the shared ring: the quiet socket's recv never
	 * waits for a buffer more than a handful of times. */
	ASSERT(bst_test_uring_nobufs < 20);
	bst_sock_close(vs);
	close(vb);
	run_for(l, 5);
	bst_loop_free(l);
}

/* ---- a closed socket's send never reaches the next owner of its fd number ---- */

TEST(close_unsubmitted_send_fd_reused)
{
	bst_loop *l = mk((bst_loop_cfg){0});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	size_t n = 1000;
	bst_buf *buf = bst_buf_new(n);
	memset(buf->data, 'S', n); /* client 1's private response */
	buf->len = n;
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	ASSERT_EQ(bst_chain_add_mem(&c, buf, 0, n), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0); /* not submitted yet */
	bst_sock_close(s);
	int a2, b2;
	ASSERT_EQ(tcp_pair(&a2, &b2), 0); /* a new client gets the number back */
	ASSERT_EQ(a2, a);
	run_for(l, 30);
	fcntl(b2, F_SETFL, O_NONBLOCK);
	unsigned char rb[2000];
	ssize_t k = read(b2, rb, sizeof rb);
	ASSERT(k <= 0); /* nothing of client 1's response */
	ASSERT_EQ(r.calls, 0);
	bst_chain_clear(&c);
	bst_buf_unref(buf);
	close(a2);
	close(b);
	close(b2);
	bst_slab_free(slab);
	bst_loop_free(l);
}

TAP_MAIN()

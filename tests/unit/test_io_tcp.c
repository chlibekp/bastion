#include "core/log.h"
#include "io/loop.h"
#include "io/loop_priv.h"
#include "io/net.h"
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define LOOP_OR_SKIP(l, cfg_)                                                           \
	bst_loop_cfg cfg_ = {0};                                                        \
	{                                                                               \
		const char *b_ = getenv("BST_TEST_BACKEND");                            \
		if (b_ != NULL && strcmp(b_, "epoll") != 0) {                           \
			printf("# SKIP: backend '%s' is not built yet\n", b_);          \
			return;                                                         \
		}                                                                       \
	}                                                                               \
	cfg_.backend = BST_BACKEND_EPOLL;                                               \
	bst_err err_;                                                                   \
	bst_loop *l = bst_loop_new(&cfg_, &err_);                                       \
	ASSERT(l != NULL)

/* ---- helpers ---- */

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

/* Runs until *flag (set by a callback that also stops the loop) or the deadline. */
static void run_until(bst_loop *l, volatile int *flag, uint64_t deadline_ms)
{
	if (*flag)
		return;
	run_for(l, deadline_ms);
}

static int listen_local(uint16_t *port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 128) != 0)
		return -1;
	socklen_t len = sizeof a;
	getsockname(fd, (struct sockaddr *)&a, &len);
	*port = ntohs(a.sin_port);
	return fd;
}

/* a: connecting end, b: accepted end. Both blocking. */
static int tcp_pair(int *a, int *b)
{
	uint16_t port;
	int ls = listen_local(&port);
	if (ls < 0)
		return -1;
	*a = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port),
				 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	if (connect(*a, (struct sockaddr *)&sa, sizeof sa) != 0)
		return -1;
	*b = accept(ls, NULL, NULL);
	close(ls);
	return *b < 0 ? -1 : 0;
}

static void reset_close(int fd)
{
	struct linger lg = {.l_onoff = 1, .l_linger = 0};
	setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
	close(fd);
}

static inline unsigned char pat(uint64_t i)
{
	return (unsigned char)((i * 31u) ^ (i >> 13) ^ (i >> 21));
}

static bst_buf *mem_buf(uint64_t base, size_t n)
{
	bst_buf *b = bst_buf_new(n);
	if (b == NULL)
		return NULL;
	for (size_t i = 0; i < n; i++)
		b->data[i] = pat(base + i);
	b->len = n;
	return b;
}

static int tmp_file(uint64_t size)
{
	char path[] = "/tmp/bst_io_tcp_XXXXXX";
	int fd = mkstemp(path);
	if (fd < 0)
		return -1;
	unlink(path);
	if (ftruncate(fd, (off_t)size) != 0)
		return -1;
	return fd;
}

typedef struct {
	bst_loop *l;
	int calls;
	size_t bytes;
	int err;
	volatile int done;
} sendres;

static void on_done(void *ud, size_t bytes, int err)
{
	sendres *r = ud;
	r->calls++;
	r->bytes = bytes;
	r->err = err;
	r->done = 1;
	bst_loop_stop(r->l);
}

/* ---- send_chain_large ---- */

#define LARGE_TOTAL (64ull << 20)
#define TINY_N 1500u
#define TINY_SZ 100u
#define BIG_SEGS 8u

typedef struct {
	int fd;
	uint64_t total;
	uint64_t got;
	int bad;
} reader;

static void *slow_reader(void *p)
{
	reader *r = p;
	static unsigned char buf[256 * 1024];
	for (;;) {
		ssize_t n = read(r->fd, buf, sizeof buf);
		if (n <= 0)
			break;
		for (ssize_t i = 0; i < n; i++)
			if (buf[i] != pat(r->got + (uint64_t)i)) {
				r->bad = 1;
				break;
			}
		r->got += (uint64_t)n;
		if (r->got >= r->total)
			break;
		struct timespec ts = {0, 1000000}; /* 1 ms between reads: a slow reader */
		nanosleep(&ts, NULL);
	}
	return NULL;
}

TEST(send_chain_large)
{
	LOOP_OR_SKIP(l, cfg);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	int small = 64 * 1024;
	setsockopt(b, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
	bst_slab *slab = bst_chain_slab_new(64);
	bst_chain c;
	bst_chain_init(&c, slab);
	uint64_t pos = 0;
	/* More tiny segments than IOV_MAX, to force several sendmsg calls. */
	bst_buf *tiny = mem_buf(0, (size_t)TINY_N * TINY_SZ);
	ASSERT(tiny != NULL);
	for (unsigned i = 0; i < TINY_N; i++)
		ASSERT_EQ(bst_chain_add_mem(&c, tiny, (size_t)i * TINY_SZ, TINY_SZ), 0);
	pos = (uint64_t)TINY_N * TINY_SZ;
	uint64_t seg = (LARGE_TOTAL - pos) / BIG_SEGS;
	int ffd = tmp_file(seg * (BIG_SEGS / 2));
	ASSERT(ffd >= 0);
	bst_buf *bufs[BIG_SEGS / 2];
	unsigned nb = 0;
	uint64_t foff = 0;
	for (unsigned i = 0; i < BIG_SEGS; i++) {
		uint64_t len = i == BIG_SEGS - 1 ? LARGE_TOTAL - pos : seg;
		if (i % 2 == 0) {
			bufs[nb] = mem_buf(pos, (size_t)len);
			ASSERT(bufs[nb] != NULL);
			ASSERT_EQ(bst_chain_add_mem(&c, bufs[nb], 0, (size_t)len), 0);
			nb++;
		} else {
			unsigned char *tmp = malloc((size_t)len);
			for (uint64_t k = 0; k < len; k++)
				tmp[k] = pat(pos + k);
			ASSERT_EQ(pwrite(ffd, tmp, (size_t)len, (off_t)foff), (ssize_t)len);
			free(tmp);
			ASSERT_EQ(bst_chain_add_file(&c, ffd, (off_t)foff, (off_t)len), 0);
			foff += len;
		}
		pos += len;
	}
	ASSERT_EQ(pos, LARGE_TOTAL);
	ASSERT_EQ(bst_chain_len(&c), LARGE_TOTAL);
	bst_buf_unref(tiny);
	for (unsigned i = 0; i < nb; i++)
		bst_buf_unref(bufs[i]);
	static reader rd; rd = (reader){.fd = b, .total = LARGE_TOTAL};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, slow_reader, &rd), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	ASSERT(s != NULL);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_until(l, &r.done, 25000);
	ASSERT_EQ(r.calls, 1);
	ASSERT_EQ(r.err, 0);
	ASSERT_EQ(r.bytes, LARGE_TOTAL);
	ASSERT_EQ(bst_chain_len(&c), 0);
	pthread_join(th, NULL);
	ASSERT_EQ(rd.got, LARGE_TOTAL);
	ASSERT_EQ(rd.bad, 0);
	bst_sock_close(s);
	close(b);
	close(ffd);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* ---- completion_once ---- */

TEST(completion_once)
{
	LOOP_OR_SKIP(l, cfg);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_slab *slab = bst_chain_slab_new(8);
	bst_sock *s = bst_sock_wrap(l, a);
	bst_buf *buf = mem_buf(0, 1000);
	bst_chain c;
	bst_chain_init(&c, slab);
	ASSERT_EQ(bst_chain_add_mem(&c, buf, 0, 1000), 0);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	ASSERT_EQ(r.calls, 0); /* never from inside bst_io_send */
	bst_chain c2;
	bst_chain_init(&c2, slab);
	ASSERT_EQ(bst_io_send(s, &c2, on_done, &r), -EBUSY);
	run_until(l, &r.done, 5000);
	run_for(l, 50);
	ASSERT_EQ(r.calls, 1);
	ASSERT_EQ(r.bytes, 1000);
	ASSERT_EQ(r.err, 0);
	/* Empty chain: still exactly one, asynchronous, completion. */
	r.done = 0;
	ASSERT_EQ(bst_io_send(s, &c2, on_done, &r), 0);
	ASSERT_EQ(r.calls, 1);
	run_until(l, &r.done, 5000);
	run_for(l, 30);
	ASSERT_EQ(r.calls, 2);
	ASSERT_EQ(r.bytes, 0);
	ASSERT_EQ(r.err, 0);
	/* An error completion is also single: peer resets, then we send. */
	reset_close(b);
	run_for(l, 30);
	bst_buf *big = mem_buf(0, 1 << 20);
	bst_chain c3;
	bst_chain_init(&c3, slab);
	ASSERT_EQ(bst_chain_add_mem(&c3, big, 0, 1 << 20), 0);
	r.done = 0;
	ASSERT_EQ(bst_io_send(s, &c3, on_done, &r), 0);
	run_until(l, &r.done, 5000);
	run_for(l, 50);
	ASSERT_EQ(r.calls, 3);
	ASSERT(r.err < 0);
	bst_chain_clear(&c3);
	bst_buf_unref(big);
	bst_chain_clear(&c);
	bst_buf_unref(buf);
	bst_sock_close(s);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* ---- peer_reset_midsend ---- */

typedef struct {
	int fd;
	bst_timer t;
} resetter;

static void do_reset(void *ud)
{
	resetter *r = ud;
	reset_close(r->fd);
}

static void reset_midsend(int use_file)
{
	signal(SIGPIPE, SIG_DFL); /* default disposition: a stray SIGPIPE would kill the test */
	bst_loop_cfg cfg = {.backend = BST_BACKEND_EPOLL};
	bst_err e;
	bst_loop *l = bst_loop_new(&cfg, &e);
	if (l == NULL)
		TAP_FAIL_("loop");
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_slab *slab = bst_chain_slab_new(8);
	bst_chain c;
	bst_chain_init(&c, slab);
	size_t n = 48u << 20;
	bst_buf *buf = NULL;
	int ffd = -1;
	if (use_file) {
		ffd = tmp_file(n);
		ASSERT(ffd >= 0);
		ASSERT_EQ(bst_chain_add_file(&c, ffd, 0, (off_t)n), 0);
	} else {
		buf = mem_buf(0, n);
		ASSERT_EQ(bst_chain_add_mem(&c, buf, 0, n), 0);
	}
	bst_sock *s = bst_sock_wrap(l, a);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	resetter rs = {.fd = b};
	bst_timer_init(&rs.t);
	bst_loop_timer_arm(l, &rs.t, 40, do_reset, &rs);
	run_until(l, &r.done, 10000);
	run_for(l, 30);
	ASSERT_EQ(r.calls, 1);
	ASSERT_EQ(r.err, -ECONNRESET);
	ASSERT(r.bytes < n);
	/* The error is consumed: the next write fails with EPIPE, which must not signal. */
	bst_chain_clear(&c);
	bst_chain c2;
	bst_chain_init(&c2, slab);
	bst_buf *more = mem_buf(0, 4096);
	ASSERT_EQ(bst_chain_add_mem(&c2, more, 0, 4096), 0);
	r.done = 0;
	ASSERT_EQ(bst_io_send(s, &c2, on_done, &r), 0);
	run_until(l, &r.done, 5000);
	ASSERT_EQ(r.calls, 2);
	ASSERT(r.err == -EPIPE || r.err == -ECONNRESET);
	bst_chain_clear(&c2);
	bst_buf_unref(more);
	if (use_file) {
		bst_chain_init(&c2, slab);
		ASSERT_EQ(bst_chain_add_file(&c2, ffd, 0, 4096), 0);
		r.done = 0;
		ASSERT_EQ(bst_io_send(s, &c2, on_done, &r), 0);
		run_until(l, &r.done, 5000);
		ASSERT_EQ(r.calls, 3);
		ASSERT(r.err == -EPIPE || r.err == -ECONNRESET);
		bst_chain_clear(&c2);
		close(ffd);
	}
	bst_buf_unref(buf);
	bst_sock_close(s);
	bst_slab_free(slab);
	bst_loop_free(l);
}

TEST(peer_reset_midsend)
{
	LOOP_OR_SKIP(l0, cfg0);
	bst_loop_free(l0);
	reset_midsend(0);
}

TEST(peer_reset_midsend_file)
{
	LOOP_OR_SKIP(l0, cfg0);
	bst_loop_free(l0);
	reset_midsend(1);
}

/* ---- close with a send in flight ---- */

TEST(close_with_send_in_flight)
{
	LOOP_OR_SKIP(l, cfg);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_slab *slab = bst_chain_slab_new(8);
	bst_chain c;
	bst_chain_init(&c, slab);
	bst_buf *buf = mem_buf(0, 32u << 20);
	ASSERT_EQ(bst_chain_add_mem(&c, buf, 0, 32u << 20), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_for(l, 40); /* socket buffers fill; the send is blocked on the peer */
	ASSERT_EQ(r.calls, 0);
	bst_sock_close(s);
	/* The peer now drains: nothing may call back or touch freed memory. */
	char tmp[65536];
	fcntl(b, F_SETFL, O_NONBLOCK);
	run_for(l, 30);
	while (read(b, tmp, sizeof tmp) > 0) {
	}
	run_for(l, 30);
	ASSERT_EQ(r.calls, 0);
	ASSERT(bst_chain_len(&c) > 0); /* the caller still owns what was not sent */
	bst_chain_clear(&c);
	bst_buf_unref(buf);
	close(b);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* ---- recv ---- */

typedef struct {
	bst_loop *l;
	size_t got;
	int eof;
	int err;
	int calls;
	int stop_after_first;
	bst_sock *s;
	int bad;
	volatile int done;
} recvres;

static void on_recv(void *ud, bst_buf *data, int err)
{
	recvres *r = ud;
	r->calls++;
	if (data != NULL) {
		for (size_t i = 0; i < data->len; i++)
			if (data->data[i] != pat(r->got + i))
				r->bad = 1;
		r->got += data->len;
		bst_buf_unref(data);
		if (r->stop_after_first)
			ASSERT_EQ(bst_io_recv_stop(r->s), 0);
		return;
	}
	if (err == 0)
		r->eof = 1;
	else
		r->err = err;
	r->done = 1;
	bst_loop_stop(r->l);
}

TEST(recv_eof)
{
	LOOP_OR_SKIP(l, cfg);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	recvres r = {.l = l, .s = s};
	ASSERT_EQ(bst_io_recv_start(s, on_recv, &r), 0);
	ASSERT_EQ(bst_io_recv_start(s, on_recv, &r), -EBUSY);
	unsigned char *d = malloc(40000);
	for (size_t i = 0; i < 40000; i++)
		d[i] = pat(i);
	ASSERT_EQ(write(b, d, 40000), 40000);
	free(d);
	shutdown(b, SHUT_WR);
	run_until(l, &r.done, 5000);
	ASSERT_EQ(r.eof, 1);
	ASSERT_EQ(r.err, 0);
	ASSERT_EQ(r.got, 40000);
	ASSERT_EQ(r.bad, 0);
	/* EOF ends the stream: no second callback. */
	int calls = r.calls;
	run_for(l, 30);
	ASSERT_EQ(r.calls, calls);
	bst_sock_close(s);
	close(b);
	bst_loop_free(l);
}

TEST(recv_error_reset)
{
	LOOP_OR_SKIP(l, cfg);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	recvres r = {.l = l, .s = s};
	ASSERT_EQ(bst_io_recv_start(s, on_recv, &r), 0);
	reset_close(b);
	run_until(l, &r.done, 5000);
	ASSERT_EQ(r.eof, 0);
	ASSERT_EQ(r.err, -ECONNRESET);
	bst_sock_close(s);
	bst_loop_free(l);
}

TEST(recv_stop_is_immediate)
{
	LOOP_OR_SKIP(l, cfg);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	recvres r = {.l = l, .s = s, .stop_after_first = 1};
	ASSERT_EQ(bst_io_recv_start(s, on_recv, &r), 0);
	char x[100000] = {0};
	for (size_t i = 0; i < sizeof x; i++)
		x[i] = (char)pat(i);
	ASSERT_EQ(write(b, x, sizeof x), (ssize_t)sizeof x);
	run_for(l, 60);
	ASSERT_EQ(r.calls, 1); /* stopped from inside the first callback */
	ASSERT(r.got > 0 && r.got <= BST_RECV_BUF_SIZE);
	bst_sock_close(s);
	close(b);
	bst_loop_free(l);
}

/* Two sockets with lots of pending data both make progress: no run of more than
 * BST_RECV_BUDGET callbacks on one while the other still has data. */
typedef struct {
	bst_sock *s;
	size_t got, total;
	int id;
} busy;

static int order[4096];
static int norder;

static void on_busy_recv(void *ud, bst_buf *data, int err)
{
	busy *b = ud;
	(void)err;
	if (data == NULL)
		return;
	b->got += data->len;
	if (norder < 4096)
		order[norder++] = b->id;
	bst_buf_unref(data);
}

TEST(recv_two_busy_sockets_progress)
{
	LOOP_OR_SKIP(l, cfg);
	int a1, b1, a2, b2;
	ASSERT_EQ(tcp_pair(&a1, &b1), 0);
	ASSERT_EQ(tcp_pair(&a2, &b2), 0);
	static char blk[BST_RECV_BUF_SIZE];
	memset(blk, 'x', sizeof blk);
	busy x[2] = {{.id = 1}, {.id = 2}};
	int w[2] = {b1, b2};
	for (int i = 0; i < 2; i++) {
		fcntl(w[i], F_SETFL, O_NONBLOCK);
		while (x[i].total < (1u << 20) && write(w[i], blk, sizeof blk) > 0)
			x[i].total += sizeof blk;
		ASSERT(x[i].total >= 16u * BST_RECV_BUF_SIZE); /* far above one budget */
	}
	norder = 0;
	x[0].s = bst_sock_wrap(l, a1);
	x[1].s = bst_sock_wrap(l, a2);
	ASSERT_EQ(bst_io_recv_start(x[0].s, on_busy_recv, &x[0]), 0);
	ASSERT_EQ(bst_io_recv_start(x[1].s, on_busy_recv, &x[1]), 0);
	run_for(l, 200);
	ASSERT_EQ(x[0].got, x[0].total);
	ASSERT_EQ(x[1].got, x[1].total);
	/* While both were busy the first 2*(total/BUF)-ish callbacks interleave. */
	int seen[3] = {0};
	int run = 0, maxrun = 0, prev = 0;
	size_t g[2] = {0, 0};
	for (int i = 0; i < norder; i++) {
		int id = order[i];
		g[id - 1] += BST_RECV_BUF_SIZE;
		if (g[0] >= x[0].total || g[1] >= x[1].total)
			break;
		seen[id]++;
		run = id == prev ? run + 1 : 1;
		prev = id;
		if (run > maxrun)
			maxrun = run;
	}
	ASSERT(seen[1] > 0 && seen[2] > 0);
	ASSERT((unsigned)maxrun <= BST_RECV_BUDGET);
	bst_sock_close(x[0].s);
	bst_sock_close(x[1].s);
	close(b1);
	close(b2);
	bst_loop_free(l);
}

/* ---- connect ---- */

TEST(connect_refused)
{
	LOOP_OR_SKIP(l, cfg);
	uint16_t port;
	int ls = listen_local(&port);
	ASSERT(ls >= 0);
	close(ls); /* nothing listens on port now */
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	bst_sock *s = bst_sock_wrap(l, fd);
	bst_sockaddr to = {.port = port};
	to.ip.family = BST_IP_V4;
	to.ip.b[0] = 127;
	to.ip.b[3] = 1;
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_connect(s, &to, on_done, &r), 0);
	run_until(l, &r.done, 5000);
	ASSERT_EQ(r.calls, 1);
	ASSERT_EQ(r.err, -ECONNREFUSED);
	run_for(l, 30);
	ASSERT_EQ(r.calls, 1);
	bst_sock_close(s);
	bst_loop_free(l);
}

TEST(connect_ok_then_send)
{
	LOOP_OR_SKIP(l, cfg);
	uint16_t port;
	int ls = listen_local(&port);
	ASSERT(ls >= 0);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	bst_sock *s = bst_sock_wrap(l, fd);
	bst_sockaddr to = {.port = port};
	to.ip.family = BST_IP_V4;
	to.ip.b[0] = 127;
	to.ip.b[3] = 1;
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_connect(s, &to, on_done, &r), 0);
	run_until(l, &r.done, 5000);
	ASSERT_EQ(r.calls, 1);
	ASSERT_EQ(r.err, 0);
	int pe = accept(ls, NULL, NULL);
	ASSERT(pe >= 0);
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	bst_buf *buf = mem_buf(0, 5000);
	ASSERT_EQ(bst_chain_add_mem(&c, buf, 0, 5000), 0);
	r.done = 0;
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_until(l, &r.done, 5000);
	ASSERT_EQ(r.err, 0);
	unsigned char in[5000];
	size_t got = 0;
	while (got < 5000) {
		ssize_t n = read(pe, in + got, 5000 - got);
		ASSERT(n > 0);
		got += (size_t)n;
	}
	for (size_t i = 0; i < 5000; i++)
		ASSERT_EQ(in[i], pat(i));
	bst_buf_unref(buf);
	bst_sock_close(s);
	close(pe);
	close(ls);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* ---- truncated file ---- */

TEST(sendfile_truncated_file)
{
	LOOP_OR_SKIP(l, cfg);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	size_t n = 32u << 20;
	int ffd = tmp_file(n);
	ASSERT(ffd >= 0);
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	ASSERT_EQ(bst_chain_add_file(&c, ffd, 0, (off_t)n), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_for(l, 40); /* blocked on the peer with most of the file unsent */
	ASSERT_EQ(r.calls, 0);
	ASSERT_EQ(ftruncate(ffd, 1 << 20), 0);
	/* Drain the peer so the sender continues. */
	char tmp[65536];
	fcntl(b, F_SETFL, O_NONBLOCK);
	uint64_t t0 = bst_loop_now_ms(l);
	while (!r.done && bst_loop_now_ms(l) < t0 + 8000) {
		while (read(b, tmp, sizeof tmp) > 0) {
		}
		run_for(l, 5);
	}
	ASSERT_EQ(r.calls, 1);
	ASSERT_EQ(r.err, -EIO);
	ASSERT(r.bytes < n);
	bst_sock_close(s);
	close(b);
	close(ffd);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* Cold file: pages dropped from the cache, the data still arrives intact. */
TEST(send_cold_file_readahead)
{
	LOOP_OR_SKIP(l, cfg);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	size_t n = 6u << 20;
	int ffd = tmp_file(n);
	ASSERT(ffd >= 0);
	unsigned char *tmp = malloc(n);
	for (size_t i = 0; i < n; i++)
		tmp[i] = pat(i);
	ASSERT_EQ(pwrite(ffd, tmp, n, 0), (ssize_t)n);
	free(tmp);
	fdatasync(ffd);
	posix_fadvise(ffd, 0, 0, POSIX_FADV_DONTNEED);
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	ASSERT_EQ(bst_chain_add_file(&c, ffd, 0, (off_t)n), 0);
	static reader rd; rd = (reader){.fd = b, .total = n};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, slow_reader, &rd), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_until(l, &r.done, 20000);
	ASSERT_EQ(r.err, 0);
	ASSERT_EQ(r.bytes, n);
	pthread_join(th, NULL);
	ASSERT_EQ(rd.got, n);
	ASSERT_EQ(rd.bad, 0);
	bst_sock_close(s);
	close(b);
	close(ffd);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* ---- aio ---- */

typedef struct {
	pthread_t work_thread;
	pthread_t done_thread;
	int work_ran, done_ran;
	bst_loop *l;
} aiores;

static void aio_work(void *p)
{
	aiores *r = p;
	r->work_thread = pthread_self();
	r->work_ran = 1;
}

static void aio_done(void *p)
{
	aiores *r = p;
	r->done_thread = pthread_self();
	r->done_ran = 1;
	bst_loop_stop(r->l);
}

TEST(aio_runs_off_loop)
{
	LOOP_OR_SKIP(l, cfg);
	aiores r = {.l = l};
	ASSERT_EQ(bst_aio_submit(l, aio_work, aio_done, &r), 0);
	run_for(l, 5000);
	ASSERT_EQ(r.work_ran, 1);
	ASSERT_EQ(r.done_ran, 1);
	ASSERT(!pthread_equal(r.work_thread, pthread_self()));
	ASSERT(pthread_equal(r.done_thread, pthread_self()));
	bst_loop_free(l);
}

static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static atomic_int gate_hits, done_hits;

static void gated_work(void *p)
{
	(void)p;
	pthread_mutex_lock(&gate);
	pthread_mutex_unlock(&gate);
	atomic_fetch_add(&gate_hits, 1);
}

static void counted_done(void *p)
{
	(void)p;
	atomic_fetch_add(&done_hits, 1);
}

TEST(aio_queue_is_bounded)
{
	bst_loop_cfg cfg = {.backend = BST_BACKEND_EPOLL, .aio_threads = 1, .aio_queue = 3};
	const char *bk = getenv("BST_TEST_BACKEND");
	if (bk != NULL && strcmp(bk, "epoll") != 0) {
		printf("# SKIP: backend '%s' is not built yet\n", bk);
		return;
	}
	bst_err e;
	bst_loop *l = bst_loop_new(&cfg, &e);
	ASSERT(l != NULL);
	atomic_store(&gate_hits, 0);
	atomic_store(&done_hits, 0);
	pthread_mutex_lock(&gate);
	for (int i = 0; i < 3; i++)
		ASSERT_EQ(bst_aio_submit(l, gated_work, counted_done, NULL), 0);
	ASSERT_EQ(bst_aio_submit(l, gated_work, counted_done, NULL), -EAGAIN);
	pthread_mutex_unlock(&gate);
	run_for(l, 100);
	ASSERT_EQ(atomic_load(&gate_hits), 3);
	ASSERT_EQ(atomic_load(&done_hits), 3);
	/* Slots are free again once done has run. */
	ASSERT_EQ(bst_aio_submit(l, gated_work, counted_done, NULL), 0);
	run_for(l, 100);
	ASSERT_EQ(atomic_load(&done_hits), 4);
	bst_loop_free(l);
}

TEST(aio_shutdown_runs_every_done)
{
	LOOP_OR_SKIP(l, cfg);
	atomic_store(&gate_hits, 0);
	atomic_store(&done_hits, 0);
	for (int i = 0; i < 20; i++)
		ASSERT_EQ(bst_aio_submit(l, gated_work, counted_done, NULL), 0);
	bst_loop_free(l); /* never ran: work completes, done runs from free */
	ASSERT_EQ(atomic_load(&gate_hits), 20);
	ASSERT_EQ(atomic_load(&done_hits), 20);
}

/* ---- accept ---- */

typedef struct {
	bst_loop *l;
	int fds[16];
	int n;
	int errs;
	int last_err;
	int port_ok;
	int restart_fd;
	int restart; /* restart accepting from the callback after an error */
	bst_accept_cb cb;
} accres;

static void on_accept(void *ud, int fd, const bst_sockaddr *peer, int err)
{
	accres *r = ud;
	if (err != 0) {
		r->errs++;
		r->last_err = err;
		ASSERT_EQ(fd, -1);
		bst_loop_stop(r->l);
		return;
	}
	if (peer != NULL && peer->ip.family == BST_IP_V4 && peer->ip.b[0] == 127)
		r->port_ok++;
	int fl = fcntl(fd, F_GETFL);
	int fdfl = fcntl(fd, F_GETFD);
	if (!(fl & O_NONBLOCK) || !(fdfl & FD_CLOEXEC))
		r->port_ok = -1000;
	if (r->n < 16)
		r->fds[r->n++] = fd;
	else
		close(fd);
	if (r->n >= 3)
		bst_loop_stop(r->l);
}

static int client_to(uint16_t port)
{
	int c = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port),
				 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	if (connect(c, (struct sockaddr *)&sa, sizeof sa) != 0)
		return -1;
	return c;
}

TEST(accept_loop_and_stop)
{
	LOOP_OR_SKIP(l, cfg);
	uint16_t port;
	int ls = listen_local(&port);
	ASSERT(ls >= 0);
	accres r = {.l = l};
	ASSERT_EQ(bst_io_accept_start(l, ls, on_accept, &r), 0);
	ASSERT_EQ(bst_io_accept_start(l, ls, on_accept, &r), -EEXIST);
	int c[3];
	for (int i = 0; i < 3; i++) {
		c[i] = client_to(port);
		ASSERT(c[i] >= 0);
	}
	run_for(l, 5000);
	ASSERT_EQ(r.n, 3);
	ASSERT_EQ(r.port_ok, 3);
	ASSERT_EQ(bst_io_accept_stop(l, ls), 0);
	ASSERT_EQ(bst_io_accept_stop(l, ls), -ENOENT);
	int c4 = client_to(port);
	ASSERT(c4 >= 0);
	run_for(l, 50);
	ASSERT_EQ(r.n, 3); /* stopped: the fourth stays in the backlog */
	for (int i = 0; i < r.n; i++)
		close(r.fds[i]);
	for (int i = 0; i < 3; i++)
		close(c[i]);
	close(c4);
	close(ls);
	bst_loop_free(l);
}

TEST(accept_budget_fairness)
{
	LOOP_OR_SKIP(l, cfg);
	uint16_t port;
	int ls = listen_local(&port);
	ASSERT(ls >= 0);
	accres r = {.l = l};
	int cs[BST_ACCEPT_BUDGET + 10];
	for (unsigned i = 0; i < BST_ACCEPT_BUDGET + 10; i++) {
		cs[i] = client_to(port);
		ASSERT(cs[i] >= 0);
	}
	ASSERT_EQ(bst_io_accept_start(l, ls, on_accept, &r), 0);
	/* on_accept stops the loop after 3; resume to see all arrive across wakeups. */
	for (int i = 0; i < 10 && r.n < 16; i++)
		run_for(l, 20);
	ASSERT_EQ(r.n, 16);
	for (int i = 0; i < r.n; i++)
		close(r.fds[i]);
	for (unsigned i = 0; i < BST_ACCEPT_BUDGET + 10; i++)
		close(cs[i]);
	bst_io_accept_stop(l, ls);
	close(ls);
	bst_loop_free(l);
}

static int emfile_phase;
static void on_accept_emfile(void *ud, int fd, const bst_sockaddr *peer, int err)
{
	accres *r = ud;
	(void)peer;
	if (err != 0) {
		r->errs++;
		r->last_err = err;
		bst_loop_stop(r->l);
		return;
	}
	r->n++;
	close(fd);
	if (emfile_phase)
		bst_loop_stop(r->l);
}

TEST(accept_emfile_pauses_not_spins)
{
	LOOP_OR_SKIP(l, cfg);
	uint16_t port;
	int ls = listen_local(&port);
	ASSERT(ls >= 0);
	int c = client_to(port);
	ASSERT(c >= 0);
	struct rlimit old, lowered;
	ASSERT_EQ(getrlimit(RLIMIT_NOFILE, &old), 0);
	/* Fill every descriptor below a lowered limit. */
	int hog[64], nh = 0;
	int top = dup(0);
	close(top);
	lowered = old;
	lowered.rlim_cur = (rlim_t)(top + 4);
	ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &lowered), 0);
	for (;;) {
		int f = dup(0);
		if (f < 0)
			break;
		if (nh < 64)
			hog[nh++] = f;
		else
			close(f);
	}
	accres r = {.l = l};
	ASSERT_EQ(bst_io_accept_start(l, ls, on_accept_emfile, &r), 0);
	run_for(l, 100);
	ASSERT_EQ(r.errs, 1); /* reported once, then paused: no busy loop */
	ASSERT_EQ(r.last_err, -EMFILE);
	run_for(l, 100);
	ASSERT_EQ(r.errs, 1);
	ASSERT_EQ(r.n, 0);
	/* Free descriptors and restart: the queued connection is accepted. */
	for (int i = 0; i < nh; i++)
		close(hog[i]);
	ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &old), 0);
	emfile_phase = 1;
	ASSERT_EQ(bst_io_accept_start(l, ls, on_accept_emfile, &r), 0);
	run_for(l, 5000);
	ASSERT_EQ(r.n, 1);
	emfile_phase = 0;
	bst_io_accept_stop(l, ls);
	close(c);
	close(ls);
	bst_loop_free(l);
}

TAP_MAIN()

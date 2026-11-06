/* io_uring-only behaviour. Runs on io_uring whatever BST_TEST_BACKEND says; the shared
 * suites (test_loop, test_io_tcp) cover the common API on both backends. */
#include "core/log.h"
#include "io/loop.h"
#include "io/net.h"
#include "io/uring_priv.h"
#include "tap.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---- helpers ---- */

static bst_loop *uloop(bst_loop_cfg cfg)
{
	cfg.backend = BST_BACKEND_URING;
	bst_err e;
	bst_loop *l = bst_loop_new(&cfg, &e);
	if (l == NULL)
		printf("# bst_loop_new: %s\n", e.msg);
	return l;
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

static uint64_t mono_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Runs until *flag or the deadline, in short slices (callbacks need not stop the loop). */
static void run_until(bst_loop *l, volatile int *flag, uint64_t deadline_ms)
{
	uint64_t end = mono_ms() + deadline_ms;
	while (!*flag && mono_ms() < end)
		run_for(l, 5);
}

static int listen_local(uint16_t *port, int backlog)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, backlog) != 0)
		return -1;
	socklen_t len = sizeof a;
	getsockname(fd, (struct sockaddr *)&a, &len);
	*port = ntohs(a.sin_port);
	return fd;
}

static int client_to(uint16_t port)
{
	int c = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port),
				 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	if (c >= 0 && connect(c, (struct sockaddr *)&sa, sizeof sa) != 0) {
		close(c);
		return -1;
	}
	return c;
}

/* a: connecting end, b: accepted end. Both blocking. */
static int tcp_pair(int *a, int *b)
{
	uint16_t port;
	int ls = listen_local(&port, 16);
	if (ls < 0)
		return -1;
	*a = client_to(port);
	*b = accept(ls, NULL, NULL);
	close(ls);
	return *a < 0 || *b < 0 ? -1 : 0;
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

/* Writes total pattern bytes to fd from a thread (blocking), then optionally shuts down. */
typedef struct {
	int fd;
	size_t total;
	int shut;
	size_t start; /* bytes already written */
} writer;

static void *write_thread(void *p)
{
	writer *w = p;
	static __thread unsigned char buf[65536];
	size_t done = w->start;
	while (done < w->total) {
		size_t n = w->total - done < sizeof buf ? w->total - done : sizeof buf;
		for (size_t i = 0; i < n; i++)
			buf[i] = pat(done + i);
		ssize_t r = write(w->fd, buf, n);
		if (r <= 0)
			break;
		done += (size_t)r;
	}
	if (w->shut)
		shutdown(w->fd, SHUT_WR);
	return NULL;
}

/* Reads total bytes from fd and checks the pattern. */
typedef struct {
	int fd;
	uint64_t total, got;
	int bad;
} reader;

static void *read_thread(void *p)
{
	reader *r = p;
	static __thread unsigned char buf[65536];
	while (r->got < r->total) {
		ssize_t n = read(r->fd, buf, sizeof buf);
		if (n <= 0)
			break;
		for (ssize_t i = 0; i < n; i++)
			if (buf[i] != pat(r->got + (uint64_t)i))
				r->bad = 1;
		r->got += (uint64_t)n;
	}
	return NULL;
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
}

static const char *test_dir(void)
{
	static char d[256];
	if (d[0] == 0) {
		const char *e = getenv("BST_TEST_TMPDIR");
		char root[200];
		if (e != NULL && e[0])
			snprintf(d, sizeof d, "%s", e);
		else if (getcwd(root, sizeof root) != NULL) /* the repo root under make */
			snprintf(d, sizeof d, "%s/build/io_tcp_tmp", root);
		else
			snprintf(d, sizeof d, "/tmp");
		(void)mkdir(d, 0700);
	}
	return d;
}

/* A file of n pattern bytes, pattern position = file offset + base. */
static int pat_file(size_t n, uint64_t base)
{
	char path[300];
	snprintf(path, sizeof path, "%s/bst_uring_XXXXXX", test_dir());
	int fd = mkstemp(path);
	if (fd < 0)
		return -1;
	unlink(path);
	unsigned char *tmp = malloc(n);
	for (size_t i = 0; i < n; i++)
		tmp[i] = pat(base + i);
	ssize_t w = pwrite(fd, tmp, n, 0);
	free(tmp);
	if (w != (ssize_t)n) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Captures the logger into a pipe; log_end returns what was written. */
static int log_pipe[2] = {-1, -1};
static void log_begin(int lv)
{
	if (pipe2(log_pipe, O_NONBLOCK) == 0)
		bst_log_init(log_pipe[1], lv);
}
static void log_end(char *out, size_t cap)
{
	bst_log_init(STDERR_FILENO, BST_LOG_WARN);
	ssize_t n = read(log_pipe[0], out, cap - 1);
	out[n > 0 ? n : 0] = 0;
	close(log_pipe[0]);
	close(log_pipe[1]);
}

static int count_open_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	int n = 0;
	if (d == NULL)
		return -1;
	while (readdir(d) != NULL)
		n++;
	closedir(d);
	return n;
}

/* ---- multishot_accept_burst ---- */

typedef struct {
	bst_loop *l;
	int n, errs, target;
} accres;

static void on_accept_count(void *ud, int fd, const bst_sockaddr *peer, int err)
{
	accres *r = ud;
	(void)peer;
	if (err != 0) {
		r->errs++;
		return;
	}
	close(fd);
	if (++r->n == r->target)
		bst_loop_stop(r->l);
}

typedef struct {
	uint16_t port;
	int n, fail;
} connector;

static void *connect_thread(void *p)
{
	connector *c = p;
	for (int i = 0; i < c->n; i++) {
		int fd = client_to(c->port);
		if (fd < 0)
			c->fail++;
		else
			close(fd);
	}
	return NULL;
}

TEST(multishot_accept_burst)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	uint16_t port;
	int ls = listen_local(&port, 128);
	ASSERT(ls >= 0);
	accres r = {.l = l, .target = 1000};
	bst_test_uring_accept_arms = 0;
	ASSERT_EQ(bst_io_accept_start(l, ls, on_accept_count, &r), 0);
	connector c = {.port = port, .n = 1000};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, connect_thread, &c), 0);
	uint64_t end = mono_ms() + 20000;
	while (r.n < 1000 && mono_ms() < end)
		run_for(l, 50);
	pthread_join(th, NULL);
	run_for(l, 50); /* nothing more may arrive */
	ASSERT_EQ(c.fail, 0);
	ASSERT_EQ(r.errs, 0);
	ASSERT_EQ(r.n, 1000);
	/* Multishot: one SQE serves many connections (re-armed only if the kernel ends it). */
	ASSERT(bst_uring_features_(l) & BST_URF_ACCEPT_MSHOT);
	ASSERT(bst_test_uring_accept_arms < 50);
	ASSERT_EQ(bst_io_accept_stop(l, ls), 0);
	close(ls);
	bst_loop_free(l);
}

/* ---- recv helpers ---- */

typedef struct {
	bst_loop *l;
	bst_sock *s;
	size_t got, want;
	int bad, err, eof, errcb;
	volatile int done;
	/* holding */
	bst_buf *held[64];
	int nheld, max_held, hold_all;
	bst_timer t;
	unsigned release_ms;
} rx;

static void rx_check(rx *r, const bst_buf *b)
{
	for (size_t i = 0; i < b->len; i++)
		if (b->data[i] != pat(r->got + i)) {
			r->bad = 1;
			break;
		}
	r->got += b->len;
	if (r->got >= r->want)
		r->done = 1;
}

static void on_rx(void *ud, bst_buf *data, int err)
{
	rx *r = ud;
	if (data == NULL) {
		if (err == 0)
			r->eof = 1;
		else
			r->err = err;
		r->errcb++;
		r->done = 1;
		return;
	}
	rx_check(r, data);
	if ((r->hold_all || r->release_ms) && r->nheld < 64) {
		r->held[r->nheld++] = data;
		if (r->nheld > r->max_held)
			r->max_held = r->nheld;
	} else {
		bst_buf_unref(data);
	}
}

static void rx_release_one(void *ud)
{
	rx *r = ud;
	if (r->nheld > 0) {
		bst_buf_unref(r->held[0]);
		memmove(r->held, r->held + 1, (size_t)(r->nheld - 1) * sizeof r->held[0]);
		r->nheld--;
	}
	if (!r->done)
		bst_loop_timer_arm(r->l, &r->t, r->release_ms, rx_release_one, r);
}

static void rx_release_all(rx *r)
{
	for (int i = 0; i < r->nheld; i++)
		bst_buf_unref(r->held[i]);
	r->nheld = 0;
}

/* ---- multishot_recv_rearms ---- */

TEST(multishot_recv_rearms)
{
	/* A CQ of 8: the kernel ends a multishot recv once the CQ is full, the backend must
	 * arm it again by itself. */
	bst_test_uring_cq = 8;
	bst_loop *l = uloop((bst_loop_cfg){.uring_entries = 4});
	bst_test_uring_cq = 0;
	ASSERT(l != NULL);
	ASSERT(bst_uring_features_(l) & BST_URF_RECV_MSHOT);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	/* Queue far more than 8 buffers' worth in the socket first, so the first multishot
	 * recv fills the CQ in one go, whatever the speed of the writer thread afterwards. */
	int big = 1 << 20;
	setsockopt(a, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
	setsockopt(b, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
	fcntl(b, F_SETFL, O_NONBLOCK);
	size_t pre = 0;
	static unsigned char chunk[16384];
	while (pre < (512u << 10)) {
		for (size_t i = 0; i < sizeof chunk; i++)
			chunk[i] = pat(pre + i);
		ssize_t k = write(b, chunk, sizeof chunk);
		if (k <= 0)
			break;
		pre += (size_t)k;
	}
	ASSERT(pre >= 16u * BST_RECV_BUF_SIZE);
	fcntl(b, F_SETFL, 0);
	bst_sock *s = bst_sock_wrap(l, a);
	rx r = {.l = l, .s = s, .want = 1u << 20};
	bst_test_uring_rearms = 0;
	ASSERT_EQ(bst_io_recv_start(s, on_rx, &r), 0);
	writer w = {.fd = b, .total = 1u << 20, .start = pre};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, write_thread, &w), 0);
	run_until(l, &r.done, 10000);
	pthread_join(th, NULL);
	ASSERT_EQ(r.got, 1u << 20);
	ASSERT_EQ(r.bad, 0);
	ASSERT_EQ(r.errcb, 0);
	ASSERT(bst_test_uring_rearms > 0);
	ASSERT_EQ(bst_test_uring_dropped(l), 0);
	bst_sock_close(s);
	close(b);
	bst_loop_free(l);
}

/* ---- buffer_exhaustion ---- */

TEST(buffer_exhaustion)
{
	bst_loop *l = uloop((bst_loop_cfg){.uring_bufs = 4});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	rx r = {.l = l, .s = s, .want = 1u << 20, .release_ms = 1};
	bst_timer_init(&r.t);
	bst_test_uring_nobufs = 0;
	ASSERT_EQ(bst_io_recv_start(s, on_rx, &r), 0);
	bst_loop_timer_arm(l, &r.t, 1, rx_release_one, &r);
	writer w = {.fd = b, .total = 1u << 20};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, write_thread, &w), 0);
	run_until(l, &r.done, 20000);
	pthread_join(th, NULL);
	bst_timer_cancel(&r.t);
	rx_release_all(&r);
	ASSERT_EQ(r.got, 1u << 20); /* every byte, */
	ASSERT_EQ(r.bad, 0);        /* in order, */
	ASSERT_EQ(r.errcb, 0);      /* and running out is not an error for the caller */
	ASSERT(r.max_held <= 4);
	ASSERT(bst_test_uring_nobufs > 0); /* the ring really ran dry */
	bst_sock_close(s);
	close(b);
	bst_loop_free(l);
}

/* ---- multishot recv ended by -ENOBUFS is re-armed when buffers return ---- */

TEST(multishot_recv_enobufs_rearmed)
{
	bst_loop *l = uloop((bst_loop_cfg){.uring_bufs = 4});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	rx r = {.l = l, .s = s, .want = 256u << 10, .hold_all = 1};
	bst_test_uring_nobufs = 0;
	ASSERT_EQ(bst_io_recv_start(s, on_rx, &r), 0);
	writer w = {.fd = b, .total = 256u << 10};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, write_thread, &w), 0);
	run_for(l, 100);
	ASSERT_EQ(r.nheld, 4);             /* every buffer is in our hands */
	ASSERT(bst_test_uring_nobufs > 0); /* and the multishot recv ended with -ENOBUFS */
	ASSERT(!s->u.r_live);
	ASSERT(s->u.r_wait);
	ASSERT_EQ(r.errcb, 0);
	size_t before = r.got;
	run_for(l, 30);
	ASSERT_EQ(r.got, before); /* nothing more without buffers */
	r.hold_all = 0;
	rx_release_all(&r); /* buffers return: the recv comes back by itself */
	run_until(l, &r.done, 10000);
	pthread_join(th, NULL);
	ASSERT_EQ(r.got, 256u << 10);
	ASSERT_EQ(r.bad, 0);
	ASSERT_EQ(r.errcb, 0);
	bst_sock_close(s);
	close(b);
	bst_loop_free(l);
}

/* ---- cq_overflow ---- */

#define NPOLL 64
static int poll_hits[NPOLL];
static void on_poll_idx(void *ud, uint32_t ev, int err)
{
	(void)err;
	if (ev & POLLIN)
		poll_hits[(intptr_t)ud]++;
}

TEST(cq_overflow)
{
	bst_test_uring_cq = 8;
	bst_loop *l = uloop((bst_loop_cfg){.uring_entries = 4});
	bst_test_uring_cq = 0;
	ASSERT(l != NULL);
	int sv[NPOLL][2];
	bst_sock *s[NPOLL];
	memset(poll_hits, 0, sizeof poll_hits);
	for (int i = 0; i < NPOLL; i++) {
		ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]), 0);
		ASSERT_EQ(write(sv[i][1], "x", 1), 1);
		s[i] = bst_sock_wrap(l, sv[i][0]);
	}
	bst_test_uring_overflows = 0;
	for (int round = 1; round <= 2; round++) {
		/* 64 completions at once into a CQ of 8: most go to the kernel's overflow list */
		for (int i = 0; i < NPOLL; i++)
			ASSERT_EQ(bst_io_poll(s[i], POLLIN, on_poll_idx, (void *)(intptr_t)i), 0);
		run_for(l, 100);
		for (int i = 0; i < NPOLL; i++)
			ASSERT_EQ(poll_hits[i], round); /* each exactly once: none lost, none twice */
	}
	ASSERT(bst_test_uring_overflows > 0); /* IORING_SQ_CQ_OVERFLOW seen and flushed */
	ASSERT_EQ(bst_test_uring_dropped(l), 0);
	for (int i = 0; i < NPOLL; i++) {
		bst_sock_close(s[i]);
		close(sv[i][1]);
	}
	bst_loop_free(l);
}

/* ---- splice_file_send ---- */

TEST(splice_file_send)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	/* mem [0,1000) file A [1000, 1000+3 MiB+5) (at file offset 4097: not page aligned)
	 * mem 5000 bytes, file B 100000 bytes, mem 7 bytes */
	size_t la = (3u << 20) + 5, lb = 100000;
	uint64_t pos = 0;
	bst_slab *slab = bst_chain_slab_new(8);
	bst_chain c;
	bst_chain_init(&c, slab);
	bst_buf *m1 = mem_buf(pos, 1000);
	ASSERT_EQ(bst_chain_add_mem(&c, m1, 0, 1000), 0);
	pos += 1000;
	int fa = pat_file(4097 + la, pos - 4097);
	ASSERT(fa >= 0);
	ASSERT_EQ(bst_chain_add_file(&c, fa, 4097, (off_t)la), 0);
	pos += la;
	bst_buf *m2 = mem_buf(pos, 5000);
	ASSERT_EQ(bst_chain_add_mem(&c, m2, 0, 5000), 0);
	pos += 5000;
	int fb = pat_file(lb, pos);
	ASSERT(fb >= 0);
	ASSERT_EQ(bst_chain_add_file(&c, fb, 0, (off_t)lb), 0);
	pos += lb;
	bst_buf *m3 = mem_buf(pos, 7);
	ASSERT_EQ(bst_chain_add_mem(&c, m3, 0, 7), 0);
	pos += 7;
	/* both sends: the second one is file C, whose pattern continues the stream */
	reader rd = {.fd = b, .total = pos + 4096};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, read_thread, &rd), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	sendres r = {.l = l};
	bst_test_uring_splices = 0;
	bst_test_uring_pipes_made = 0;
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_until(l, &r.done, 20000);
	ASSERT_EQ(r.calls, 1);
	ASSERT_EQ(r.err, 0);
	ASSERT_EQ(r.bytes, pos);
	ASSERT_EQ(bst_chain_len(&c), 0);
	ASSERT(bst_test_uring_splices >= 2); /* file bytes went through the pipe */
	ASSERT_EQ(bst_test_uring_pipes_made, 1);
	/* A second file send reuses the pooled pipe. */
	int fc = pat_file(4096, pos);
	ASSERT(fc >= 0);
	ASSERT_EQ(bst_chain_add_file(&c, fc, 0, 4096), 0);
	r.done = 0;
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_until(l, &r.done, 5000);
	ASSERT_EQ(r.err, 0);
	ASSERT_EQ(bst_test_uring_pipes_made, 1);
	pthread_join(th, NULL);
	ASSERT_EQ(rd.got, pos + 4096);
	ASSERT_EQ(rd.bad, 0); /* byte-identical, in order, across memory and file segments */
	bst_sock_close(s);
	close(b);
	close(fa);
	close(fb);
	close(fc);
	bst_buf_unref(m1);
	bst_buf_unref(m2);
	bst_buf_unref(m3);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* ---- stale generation after close and reuse ---- */

static int in_calls, out_calls;
static uint32_t out_ev;
static void on_in(void *ud, uint32_t ev, int err)
{
	(void)ud;
	(void)ev;
	(void)err;
	in_calls++;
}
static void on_out(void *ud, uint32_t ev, int err)
{
	(void)ud;
	(void)err;
	out_calls++;
	out_ev = ev;
}

TEST(stale_generation_dropped_after_close_and_reuse)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	bst_uring *u = l->be;
	/* 1. A poll replaced before it ran: the old arm completes (POLLIN is ready) and must
	 * be dropped by its tag; the new POLLOUT arm must still be delivered. */
	int p[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
	ASSERT_EQ(write(p[1], "x", 1), 1);
	bst_sock *s = bst_sock_wrap(l, p[0]);
	in_calls = out_calls = 0;
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_in, NULL), 0);
	uint16_t firsttag = (uint16_t)s->gen; /* s's first arm: what a reused address must not match */
	ASSERT_EQ(bst_io_poll(s, POLLOUT, on_out, NULL), 0);
	run_for(l, 30);
	ASSERT_EQ(in_calls, 0);
	ASSERT_EQ(out_calls, 1);
	ASSERT(out_ev & POLLOUT);
	ASSERT_EQ(s->inflight, 0);
	/* 2. Close with the poll's completion still to come, and reuse the fd number at once:
	 * the old completion belongs to the closed socket, never to the new one. */
	ASSERT_EQ(bst_io_poll(s, POLLIN, on_in, NULL), 0);
	int oldfd = s->fd;
	bst_sock_close(s);
	int q[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, q), 0);
	ASSERT_EQ(q[0], oldfd); /* the number really is reused */
	bst_sock *s2 = bst_sock_wrap(l, q[0]);
	ASSERT(s2 != s); /* s is still in flight: its memory is not reused yet */
	ASSERT_EQ(bst_io_poll(s2, POLLIN, on_out, NULL), 0);
	out_calls = 0;
	run_for(l, 30);
	ASSERT_EQ(in_calls, 0);
	ASSERT_EQ(out_calls, 0); /* q[1] wrote nothing yet */
	ASSERT_EQ(write(q[1], "y", 1), 1);
	run_for(l, 30);
	ASSERT_EQ(out_calls, 1);
	/* 3. s is freed now; the next socket gets its memory. A completion carrying s's old
	 * tag (injected: a NOP with that user_data) must not count as the new socket's arm. */
	int r2[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, r2), 0);
	bst_sock *s3 = bst_sock_wrap(l, r2[0]);
	ASSERT(s3 == s);
	ASSERT_EQ(bst_io_poll(s3, POLLIN, on_in, NULL), 0); /* s3's first arm, like firsttag */
	ASSERT((uint16_t)s3->gen != firsttag); /* generations do not restart at a reused address */
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	ASSERT(sqe != NULL);
	io_uring_prep_nop(sqe);
	bst_uring_prep_(u, sqe, BST_UK_POLL, s3, firsttag);
	run_for(l, 30);
	ASSERT_EQ(in_calls, 0);
	ASSERT_EQ(s3->inflight, 1); /* the stale one released, its own poll still armed */
	ASSERT(s3->u.poll_live);
	ASSERT_EQ(write(r2[1], "z", 1), 1);
	run_for(l, 30);
	ASSERT_EQ(in_calls, 1);
	bst_sock_close(s2);
	bst_sock_close(s3);
	close(p[1]);
	close(q[1]);
	close(r2[1]);
	bst_loop_free(l);
}

/* ---- ring drain at bst_loop_free ---- */

static void on_rx_drop(void *ud, bst_buf *data, int err)
{
	(void)ud;
	(void)err;
	bst_buf_unref(data);
}

static void drain_case(int run_first)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	int a1, b1, a2, b2, a3, b3;
	ASSERT_EQ(tcp_pair(&a1, &b1), 0);
	ASSERT_EQ(tcp_pair(&a2, &b2), 0);
	ASSERT_EQ(tcp_pair(&a3, &b3), 0);
	bst_sock *s1 = bst_sock_wrap(l, a1), *s2 = bst_sock_wrap(l, a2), *s3 = bst_sock_wrap(l, a3);
	ASSERT_EQ(bst_io_recv_start(s1, on_rx_drop, NULL), 0);
	ASSERT_EQ(bst_io_recv_start(s2, on_rx_drop, NULL), 0);
	ASSERT_EQ(bst_io_poll(s2, POLLOUT | POLLIN, on_in, NULL), 0);
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	bst_buf *big = mem_buf(0, 32u << 20); /* far more than the socket buffers hold */
	ASSERT_EQ(bst_chain_add_mem(&c, big, 0, 32u << 20), 0);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s3, &c, on_done, &r), 0);
	if (run_first)
		run_for(l, 30); /* every operation is in the kernel now */
	in_calls = 0;
	bst_sock_close(s1);
	bst_sock_close(s2);
	bst_sock_close(s3);
	/* The caller may free what the send used as soon as close returns. */
	bst_chain_clear(&c);
	bst_buf_unref(big);
	ASSERT(bst_test_uring_live(l) >= 3); /* two recvs and the send, at least */
	bst_test_uring_drained = 0;
	bst_loop_free(l); /* cancels and reaps everything before freeing: ASan stays quiet */
	ASSERT(bst_test_uring_drained >= 3);
	ASSERT_EQ(r.calls, 0);
	ASSERT_EQ(in_calls, 0);
	close(b1);
	close(b2);
	close(b3);
	bst_slab_free(slab);
}

TEST(ring_drain_at_loop_free)
{
	drain_case(1);
	drain_case(0); /* closed before anything was even submitted */
}

/* The kernel did not finish in time (simulated with a zero bound): logged, memory kept. */
TEST(ring_drain_timeout_logs)
{
	fflush(stdout);
	pid_t pid = fork();
	ASSERT(pid >= 0);
	if (pid == 0) {
		bst_test_uring_drain_ms = 0;
		bst_loop *l = uloop((bst_loop_cfg){0});
		int a, b;
		if (l == NULL || tcp_pair(&a, &b) != 0)
			_exit(2);
		bst_sock *s = bst_sock_wrap(l, a);
		bst_io_recv_start(s, on_rx_drop, NULL);
		run_for(l, 10);
		bst_sock_close(s);
		char buf[512];
		log_begin(BST_LOG_ERROR);
		bst_loop_free(l);
		log_end(buf, sizeof buf);
		/* _exit: the leak is deliberate, LeakSanitizer must not run */
		_exit(strstr(buf, "still in flight") != NULL ? 0 : 3);
	}
	int st = 0;
	ASSERT_EQ(waitpid(pid, &st, 0), pid);
	ASSERT(WIFEXITED(st));
	ASSERT_EQ(WEXITSTATUS(st), 0);
}

/* ---- setup: flag ladder, disabled ring, restrictions ---- */

static int poll_once(bst_loop *l)
{
	int p[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) != 0)
		return -1;
	bst_sock *s = bst_sock_wrap(l, p[0]);
	(void)!write(p[1], "x", 1);
	in_calls = 0;
	if (bst_io_poll(s, POLLIN, on_in, NULL) != 0)
		return -1;
	run_for(l, 30);
	bst_sock_close(s);
	close(p[1]);
	return in_calls;
}

TEST(flag_ladder_steps_down)
{
	const unsigned all = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN |
			     IORING_SETUP_COOP_TASKRUN;
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	unsigned f = bst_uring_setup_flags_(l);
	ASSERT_EQ(f & (all | IORING_SETUP_R_DISABLED), all | IORING_SETUP_R_DISABLED);
	bst_loop_free(l);
	struct {
		unsigned reject, expect;
	} rungs[] = {
		{IORING_SETUP_DEFER_TASKRUN, IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN},
		{IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER, IORING_SETUP_COOP_TASKRUN},
		{all, 0},
	};
	for (unsigned i = 0; i < sizeof rungs / sizeof rungs[0]; i++) {
		bst_test_uring_reject = rungs[i].reject;
		l = uloop((bst_loop_cfg){0});
		bst_test_uring_reject = 0;
		ASSERT(l != NULL);
		f = bst_uring_setup_flags_(l);
		ASSERT_EQ(f & all, rungs[i].expect);
		ASSERT(f & IORING_SETUP_R_DISABLED);
		ASSERT_EQ(poll_once(l), 1); /* and it works */
		bst_loop_free(l);
	}
	/* R_DISABLED is required (Task 8 restricts before enabling): no ring without it. */
	bst_test_uring_reject = IORING_SETUP_R_DISABLED;
	bst_loop_cfg cfg = {.backend = BST_BACKEND_URING};
	bst_err e;
	l = bst_loop_new(&cfg, &e);
	bst_test_uring_reject = 0;
	ASSERT(l == NULL);
	ASSERT(strstr(e.msg, "io_uring") != NULL);
}

static int hook_calls, hook_was_disabled;
static int restrict_hook(struct io_uring *ring)
{
	hook_calls++;
	/* Disabled: submitting is refused until the ring is enabled. */
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	hook_was_disabled = io_uring_submit(ring) == -EBADFD;
	struct io_uring_restriction res[64];
	unsigned n = 0;
	memset(res, 0, sizeof res);
	for (unsigned i = 0; i < bst_uring_nopcodes_; i++) {
		res[n].opcode = IORING_RESTRICTION_SQE_OP;
		res[n++].sqe_op = bst_uring_opcodes_[i];
	}
	res[n].opcode = IORING_RESTRICTION_SQE_FLAGS_ALLOWED;
	res[n++].sqe_flags = BST_URING_SQE_FLAGS;
	for (unsigned i = 0; i < bst_uring_nregister_; i++) {
		res[n].opcode = IORING_RESTRICTION_REGISTER_OP;
		res[n++].register_op = bst_uring_register_ops_[i];
	}
	return io_uring_register_restrictions(ring, res, n);
}

static int fail_hook(struct io_uring *ring)
{
	(void)ring;
	return -EPERM;
}

static void on_accept_keep(void *ud, int fd, const bst_sockaddr *peer, int err)
{
	(void)peer;
	if (err == 0)
		*(int *)ud = fd;
}

/* Everything the backend does (accept, recv, send with a file segment, poll, connect,
 * wake, empty send, cancel at close) works on a ring restricted to its declared opcodes. */
TEST(ring_disabled_until_hook_then_restricted)
{
	hook_calls = hook_was_disabled = 0;
	bst_uring_pre_enable_ = restrict_hook;
	bst_loop *l = uloop((bst_loop_cfg){0});
	bst_uring_pre_enable_ = NULL;
	ASSERT(l != NULL);
	ASSERT_EQ(hook_calls, 1);
	ASSERT_EQ(hook_was_disabled, 1);
	/* the restriction itself took: a register op we did not allow fails */
	ASSERT_EQ(io_uring_register_restrictions(bst_test_uring_ring(l), NULL, 0) < 0, 1);
	uint16_t port;
	int ls = listen_local(&port, 16);
	int acc = -1;
	ASSERT_EQ(bst_io_accept_start(l, ls, on_accept_keep, &acc), 0);
	int cfd = socket(AF_INET, SOCK_STREAM, 0);
	bst_sock *cs = bst_sock_wrap(l, cfd);
	bst_sockaddr to = {.port = port};
	to.ip.family = BST_IP_V4;
	to.ip.b[0] = 127;
	to.ip.b[3] = 1;
	sendres cr = {.l = l};
	ASSERT_EQ(bst_io_connect(cs, &to, on_done, &cr), 0);
	run_until(l, &cr.done, 5000);
	ASSERT_EQ(cr.err, 0);
	for (int i = 0; i < 100 && acc < 0; i++)
		run_for(l, 5);
	ASSERT(acc >= 0);
	bst_sock *ss = bst_sock_wrap(l, acc);
	rx r = {.l = l, .s = ss, .want = 1000 + 70000};
	ASSERT_EQ(bst_io_recv_start(ss, on_rx, &r), 0);
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	bst_buf *m = mem_buf(0, 1000);
	ASSERT_EQ(bst_chain_add_mem(&c, m, 0, 1000), 0);
	int f = pat_file(70000, 1000);
	ASSERT(f >= 0);
	ASSERT_EQ(bst_chain_add_file(&c, f, 0, 70000), 0);
	sendres sr = {.l = l};
	ASSERT_EQ(bst_io_send(cs, &c, on_done, &sr), 0);
	run_until(l, &sr.done, 5000);
	ASSERT_EQ(sr.err, 0);
	run_until(l, &r.done, 5000);
	ASSERT_EQ(r.got, 71000);
	ASSERT_EQ(r.bad, 0);
	sr.done = 0;
	ASSERT_EQ(bst_io_send(cs, &c, on_done, &sr), 0); /* empty chain */
	run_until(l, &sr.done, 5000);
	ASSERT_EQ(sr.err, 0);
	ASSERT_EQ(poll_once(l), 1);
	bst_sock_close(cs);
	bst_sock_close(ss);
	bst_io_accept_stop(l, ls);
	close(ls);
	close(f);
	bst_buf_unref(m);
	bst_slab_free(slab);
	bst_loop_free(l);

	bst_uring_pre_enable_ = fail_hook;
	bst_loop_cfg cfg = {.backend = BST_BACKEND_URING};
	bst_err e;
	l = bst_loop_new(&cfg, &e);
	bst_uring_pre_enable_ = NULL;
	ASSERT(l == NULL);
	ASSERT(strstr(e.msg, "restrict") != NULL);
}

/* ---- single-shot fallbacks ---- */

TEST(single_shot_fallback)
{
	bst_test_uring_nofeat = BST_URF_RECV_MSHOT | BST_URF_ACCEPT_MSHOT;
	bst_loop *l = uloop((bst_loop_cfg){0});
	bst_test_uring_nofeat = 0;
	ASSERT(l != NULL);
	ASSERT_EQ(bst_uring_features_(l) & (BST_URF_RECV_MSHOT | BST_URF_ACCEPT_MSHOT), 0);
	uint16_t port;
	int ls = listen_local(&port, 64);
	accres ar = {.l = l, .target = 20};
	bst_test_uring_accept_arms = 0;
	ASSERT_EQ(bst_io_accept_start(l, ls, on_accept_count, &ar), 0);
	connector cn = {.port = port, .n = 20};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, connect_thread, &cn), 0);
	uint64_t end = mono_ms() + 10000;
	while (ar.n < 20 && mono_ms() < end)
		run_for(l, 20);
	pthread_join(th, NULL);
	ASSERT_EQ(ar.n, 20);
	ASSERT(bst_test_uring_accept_arms >= 20); /* one SQE per connection */
	bst_io_accept_stop(l, ls);
	close(ls);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	rx r = {.l = l, .s = s, .want = 512u << 10};
	ASSERT_EQ(bst_io_recv_start(s, on_rx, &r), 0);
	writer w = {.fd = b, .total = 512u << 10};
	ASSERT_EQ(pthread_create(&th, NULL, write_thread, &w), 0);
	run_until(l, &r.done, 10000);
	pthread_join(th, NULL);
	ASSERT_EQ(r.got, 512u << 10);
	ASSERT_EQ(r.bad, 0);
	bst_sock_close(s);
	close(b);
	bst_loop_free(l);
}

/* ---- zero-copy sends ---- */

TEST(send_zc_above_threshold)
{
	bst_loop *l = uloop((bst_loop_cfg){.uring_send_zc_min = 4096});
	ASSERT(l != NULL);
	ASSERT(bst_uring_features_(l) & BST_URF_SENDMSG_ZC);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	size_t n = 4u << 20;
	bst_buf *buf = mem_buf(0, n);
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	ASSERT_EQ(bst_chain_add_mem(&c, buf, 0, n), 0);
	bst_buf_unref(buf); /* the chain's reference is the only one: it must outlive the send */
	reader rd = {.fd = b, .total = n};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, read_thread, &rd), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	sendres r = {.l = l};
	bst_test_uring_zc = 0;
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_until(l, &r.done, 10000);
	pthread_join(th, NULL);
	ASSERT_EQ(r.calls, 1);
	ASSERT_EQ(r.err, 0);
	ASSERT_EQ(r.bytes, n);
	ASSERT_EQ(rd.got, n);
	ASSERT_EQ(rd.bad, 0);
	ASSERT(bst_test_uring_zc > 0);
	/* Below the threshold: a plain send. */
	bst_buf *small = mem_buf(0, 100);
	ASSERT_EQ(bst_chain_add_mem(&c, small, 0, 100), 0);
	unsigned zc0 = bst_test_uring_zc;
	r.done = 0;
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_until(l, &r.done, 5000);
	ASSERT_EQ(r.err, 0);
	ASSERT_EQ(bst_test_uring_zc, zc0);
	bst_buf_unref(small);
	bst_sock_close(s);
	close(b);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* ---- SQPOLL and NAPI options ---- */

TEST(sqpoll_option)
{
	bst_loop *l = uloop((bst_loop_cfg){.uring_sqpoll = 20});
	ASSERT(l != NULL);
	ASSERT(bst_uring_setup_flags_(l) & IORING_SETUP_SQPOLL);
	ASSERT_EQ(poll_once(l), 1);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	rx r = {.l = l, .s = s, .want = 100000};
	ASSERT_EQ(bst_io_recv_start(s, on_rx, &r), 0);
	writer w = {.fd = b, .total = 100000};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, write_thread, &w), 0);
	run_until(l, &r.done, 5000);
	pthread_join(th, NULL);
	ASSERT_EQ(r.got, 100000);
	ASSERT_EQ(r.bad, 0);
	/* close with a send blocked in the kernel, then free the memory it used */
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	bst_buf *big = mem_buf(0, 16u << 20);
	ASSERT_EQ(bst_chain_add_mem(&c, big, 0, 16u << 20), 0);
	sendres sr = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &sr), 0);
	run_for(l, 20);
	bst_sock_close(s);
	bst_chain_clear(&c);
	bst_buf_unref(big);
	ASSERT_EQ(sr.calls, 0);
	close(b);
	bst_slab_free(slab);
	bst_loop_free(l);
}

TEST(napi_option)
{
	char logbuf[512];
	log_begin(BST_LOG_WARN);
	bst_loop *l = uloop((bst_loop_cfg){.uring_napi = 50});
	log_end(logbuf, sizeof logbuf);
	ASSERT(l != NULL);
	/* Linux 6.9+ registers it; older kernels say so once and run without it. */
	if (!(bst_uring_features_(l) & BST_URF_NAPI))
		ASSERT(strstr(logbuf, "NAPI") != NULL);
	else
		ASSERT_EQ(logbuf[0], 0);
	ASSERT_EQ(poll_once(l), 1);
	bst_loop_free(l);
}

/* ---- a full socket is waited for, never retried in a spin ---- */

TEST(splice_waits_for_pollout)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	int small = 64 * 1024;
	setsockopt(a, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
	setsockopt(b, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
	size_t n = 8u << 20;
	int f = pat_file(n, 0);
	ASSERT(f >= 0);
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	ASSERT_EQ(bst_chain_add_file(&c, f, 0, (off_t)n), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	sendres r = {.l = l};
	bst_test_uring_splice_outs = 0;
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_for(l, 150); /* the peer reads nothing: the socket stays full */
	ASSERT_EQ(r.calls, 0);
	ASSERT(bst_test_uring_splice_outs > 0);
	ASSERT(bst_test_uring_splice_outs <= 4); /* parked on POLLOUT, not retried */
	reader rd = {.fd = b, .total = n};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, read_thread, &rd), 0);
	run_until(l, &r.done, 20000);
	pthread_join(th, NULL);
	ASSERT_EQ(r.err, 0);
	ASSERT_EQ(rd.got, n);
	ASSERT_EQ(rd.bad, 0);
	bst_sock_close(s);
	close(b);
	close(f);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* ---- a stopped stream leaves new data in the socket (backpressure) ---- */

static void on_rx_stop_first(void *ud, bst_buf *data, int err)
{
	rx *r = ud;
	(void)err;
	if (data == NULL)
		return;
	r->got += data->len;
	bst_buf_unref(data);
	bst_io_recv_stop(r->s);
}

TEST(recv_stop_leaves_data_in_socket)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	bst_uring *u = l->be;
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	fcntl(b, F_SETFL, O_NONBLOCK);
	static unsigned char blk[65536];
	ASSERT_EQ(write(b, blk, sizeof blk), (ssize_t)sizeof blk);
	bst_sock *s = bst_sock_wrap(l, a);
	rx r = {.l = l, .s = s};
	ASSERT_EQ(bst_io_recv_start(s, on_rx_stop_first, &r), 0);
	run_for(l, 30);
	ASSERT(r.got > 0);
	ASSERT(!s->u.r_live); /* stop cancelled the multishot recv */
	unsigned taken = u->taken; /* what the recv took before the stop: kept for restart */
	ASSERT(write(b, blk, sizeof blk) > 0);
	run_for(l, 30);
	ASSERT_EQ(u->taken, taken); /* the new data stays in the kernel */
	bst_sock_close(s);
	ASSERT_EQ(u->taken, 0); /* close gives the stashed buffers back */
	close(b);
	bst_loop_free(l);
}

/* ---- accept: completions after stop never leak an fd ---- */

static void on_accept_stop_first(void *ud, int fd, const bst_sockaddr *peer, int err)
{
	accres *r = ud;
	(void)peer;
	if (err != 0)
		return;
	close(fd);
	if (r->n++ == 0)
		bst_io_accept_stop(r->l, r->target); /* target holds the listen fd here */
}

TEST(accept_stop_closes_queued_fds)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	uint16_t port;
	int ls = listen_local(&port, 64);
	int cs[20];
	for (int i = 0; i < 20; i++)
		ASSERT((cs[i] = client_to(port)) >= 0);
	int before = count_open_fds();
	accres r = {.l = l, .target = ls};
	ASSERT_EQ(bst_io_accept_start(l, ls, on_accept_stop_first, &r), 0);
	run_for(l, 50);
	ASSERT_EQ(r.n, 1); /* stopped from the first callback */
	ASSERT_EQ(count_open_fds(), before); /* the other accepted fds were closed, not leaked */
	for (int i = 0; i < 20; i++)
		close(cs[i]);
	close(ls);
	bst_loop_free(l);
}

TAP_MAIN()

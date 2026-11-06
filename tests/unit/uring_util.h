/* Helpers shared by the io_uring-only test files (test_uring_only.c, test_uring_net.c). */
#ifndef BST_TEST_URING_UTIL_H
#define BST_TEST_URING_UTIL_H

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

static inline bst_loop *uloop(bst_loop_cfg cfg)
{
	cfg.backend = BST_BACKEND_URING;
	bst_err e;
	bst_loop *l = bst_loop_new(&cfg, &e);
	if (l == NULL)
		printf("# bst_loop_new: %s\n", e.msg);
	return l;
}

static inline void on_stop_timer(void *ud)
{
	bst_loop_stop(ud);
}

static inline void run_for(bst_loop *l, uint64_t ms)
{
	bst_timer t;
	bst_timer_init(&t);
	bst_loop_timer_arm(l, &t, ms, on_stop_timer, l);
	(void)bst_loop_run(l);
	bst_timer_cancel(&t);
}

static inline uint64_t mono_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Runs until *flag or the deadline, in short slices (callbacks need not stop the loop). */
static inline void run_until(bst_loop *l, volatile int *flag, uint64_t deadline_ms)
{
	uint64_t end = mono_ms() + deadline_ms;
	while (!*flag && mono_ms() < end)
		run_for(l, 5);
}

static inline int listen_local(uint16_t *port, int backlog)
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

static inline int client_to(uint16_t port)
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
static inline int tcp_pair(int *a, int *b)
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

static inline bst_buf *mem_buf(uint64_t base, size_t n)
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

static inline void *write_thread(void *p)
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

static inline void *read_thread(void *p)
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

static inline void on_done(void *ud, size_t bytes, int err)
{
	sendres *r = ud;
	r->calls++;
	r->bytes = bytes;
	r->err = err;
	r->done = 1;
}

static inline const char *test_dir(void)
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
static inline int pat_file(size_t n, uint64_t base)
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
static int log_pipe[2] __attribute__((unused)) = {-1, -1};
static inline void log_begin(int lv)
{
	if (pipe2(log_pipe, O_NONBLOCK) == 0)
		bst_log_init(log_pipe[1], lv);
}
static inline void log_end(char *out, size_t cap)
{
	bst_log_init(STDERR_FILENO, BST_LOG_WARN);
	ssize_t n = read(log_pipe[0], out, cap - 1);
	out[n > 0 ? n : 0] = 0;
	close(log_pipe[0]);
	close(log_pipe[1]);
}

static inline int count_open_fds(void)
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

static inline void on_accept_count(void *ud, int fd, const bst_sockaddr *peer, int err)
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

static inline void *connect_thread(void *p)
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

static inline void rx_check(rx *r, const bst_buf *b)
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

static inline void on_rx(void *ud, bst_buf *data, int err)
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

static inline void rx_release_one(void *ud)
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

static inline void rx_release_all(rx *r)
{
	for (int i = 0; i < r->nheld; i++)
		bst_buf_unref(r->held[i]);
	r->nheld = 0;
}

/* ---- stale generation after close and reuse ---- */

static int in_calls __attribute__((unused)), out_calls __attribute__((unused));
static uint32_t out_ev __attribute__((unused));
static inline void on_in(void *ud, uint32_t ev, int err)
{
	(void)ud;
	(void)ev;
	(void)err;
	in_calls++;
}
static inline void on_out(void *ud, uint32_t ev, int err)
{
	(void)ud;
	(void)err;
	out_calls++;
	out_ev = ev;
}

/* ---- ring drain at bst_loop_free ---- */

static inline void on_rx_drop(void *ud, bst_buf *data, int err)
{
	(void)ud;
	(void)err;
	bst_buf_unref(data);
}

/* ---- setup: flag ladder, disabled ring, restrictions ---- */

static inline int poll_once(bst_loop *l)
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


#endif

/* Helpers shared by test_udp.c and test_udp_edge.c. */
#ifndef BST_UDP_TEST_H
#define BST_UDP_TEST_H
#include "core/log.h"
#include "io/loop.h"
#include "io/loop_priv.h"
#include "io/udp.h"
#include "io/udp_priv.h"
#include "io/uring_priv.h"
#include "tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

/* A loop that never returns (a budget gone wrong) fails the run, it does not hang it. */
static void udp_watchdog_fired(int sig)
{
	static const char msg[] = "udp test watchdog: loop did not return in 100s\n";
	(void)sig;
	(void)!write(2, msg, sizeof msg - 1);
	_exit(1);
}

static void __attribute__((constructor)) udp_watchdog(void)
{
	signal(SIGALRM, udp_watchdog_fired);
	alarm(100);
}

/* Backend-parametrised: BST_TEST_BACKEND=epoll|uring (default epoll). */
static inline bst_backend test_backend(void)
{
	const char *b = getenv("BST_TEST_BACKEND");
	return b != NULL && strcmp(b, "uring") == 0 ? BST_BACKEND_URING : BST_BACKEND_EPOLL;
}

static inline bst_loop *new_loop(unsigned udp_bufs)
{
	bst_loop_cfg cfg = {.backend = test_backend(), .uring_udp_bufs = udp_bufs};
	bst_err err;
	return bst_loop_new(&cfg, &err);
}

#define LOOP(l) bst_loop *l = new_loop(64); ASSERT(l != NULL)

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

/* ---- sockets ---- */

static inline int usock(int family, uint16_t *port, const char *ip)
{
	int fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	struct sockaddr_storage ss;
	socklen_t sl;
	memset(&ss, 0, sizeof ss);
	if (family == AF_INET) {
		struct sockaddr_in *a = (void *)&ss;
		a->sin_family = AF_INET;
		inet_pton(AF_INET, ip, &a->sin_addr);
		sl = sizeof *a;
	} else {
		struct sockaddr_in6 *a = (void *)&ss;
		a->sin6_family = AF_INET6;
		inet_pton(AF_INET6, ip, &a->sin6_addr);
		sl = sizeof *a;
	}
	if (bind(fd, (struct sockaddr *)&ss, sl) != 0) {
		close(fd);
		return -1;
	}
	getsockname(fd, (struct sockaddr *)&ss, &sl);
	*port = ntohs(family == AF_INET ? ((struct sockaddr_in *)&ss)->sin_port
					: ((struct sockaddr_in6 *)&ss)->sin6_port);
	struct timeval tv = {.tv_sec = 2};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	return fd;
}

static inline void to_addr(int family, const char *ip, uint16_t port, struct sockaddr_storage *ss,
		    socklen_t *sl)
{
	memset(ss, 0, sizeof *ss);
	if (family == AF_INET) {
		struct sockaddr_in *a = (void *)ss;
		a->sin_family = AF_INET;
		a->sin_port = htons(port);
		inet_pton(AF_INET, ip, &a->sin_addr);
		*sl = sizeof *a;
	} else {
		struct sockaddr_in6 *a = (void *)ss;
		a->sin6_family = AF_INET6;
		a->sin6_port = htons(port);
		inet_pton(AF_INET6, ip, &a->sin6_addr);
		*sl = sizeof *a;
	}
}

static inline bst_sockaddr bsa(int family, const char *ip, uint16_t port)
{
	bst_sockaddr a;
	memset(&a, 0, sizeof a);
	a.port = port;
	if (family == AF_INET) {
		a.ip.family = BST_IP_V4;
		inet_pton(AF_INET, ip, a.ip.b);
	} else {
		a.ip.family = BST_IP_V6;
		inet_pton(AF_INET6, ip, a.ip.b);
	}
	return a;
}

static inline unsigned char pat(unsigned seed, size_t i)
{
	return (unsigned char)((seed * 131u) ^ (i * 7u) ^ (i >> 5));
}

static inline void fill(unsigned char *p, size_t n, unsigned seed)
{
	for (size_t i = 0; i < n; i++)
		p[i] = pat(seed, i);
}

static inline bool check(const unsigned char *p, size_t n, unsigned seed)
{
	for (size_t i = 0; i < n; i++)
		if (p[i] != pat(seed, i))
			return false;
	return true;
}

/* ---- receive collector ---- */

#define MAXREC 1024
typedef struct {
	bst_udp_msg m;
	unsigned char *p; /* copy of the payload (NULL when the buffer is held) */
	size_t len;
} rrec;

typedef struct {
	bst_loop *l;
	rrec r[MAXREC];
	int n, calls, maxn, err, stop_at;
	bool hold;
} rx;

static inline void on_rx(void *ud, bst_udp_msg *m, int n, int err)
{
	rx *x = ud;
	x->calls++;
	if (err != 0) {
		x->err = err;
		bst_loop_stop(x->l);
		return;
	}
	if (n > x->maxn)
		x->maxn = n;
	for (int i = 0; i < n; i++) {
		if (x->n >= MAXREC) {
			bst_buf_unref(m[i].buf);
			continue;
		}
		rrec *r = &x->r[x->n++];
		r->m = m[i];
		r->len = m[i].buf->len;
		if (x->hold) {
			r->p = NULL;
		} else {
			r->p = malloc(r->len);
			memcpy(r->p, m[i].buf->data, r->len);
			bst_buf_unref(m[i].buf);
			r->m.buf = NULL;
		}
	}
	if (x->stop_at != 0 && x->n >= x->stop_at)
		bst_loop_stop(x->l);
}

static inline void rx_free(rx *x)
{
	for (int i = 0; i < x->n; i++) {
		free(x->r[i].p);
		bst_buf_unref(x->r[i].m.buf);
	}
	x->n = 0;
}

static inline void rx_wait(rx *x, int want, uint64_t ms)
{
	x->stop_at = want;
	if (x->n < want)
		run_for(x->l, ms);
}

typedef struct {
	bst_loop *l;
	int calls;
	size_t bytes;
	int err;
} sd;

static inline void on_done(void *ud, size_t bytes, int err)
{
	sd *d = ud;
	d->calls++;
	d->bytes = bytes;
	d->err = err;
	bst_loop_stop(d->l);
}

static inline void sd_wait(sd *d, uint64_t ms)
{
	if (d->calls == 0)
		run_for(d->l, ms);
}

/* a bound UDP socket wrapped on the loop, with its port */
static inline bst_sock *wrap(bst_loop *l, int family, const char *ip, uint16_t *port)
{
	int fd = usock(family, port, ip);
	if (fd < 0)
		return NULL;
	bst_sock *s = bst_sock_wrap(l, fd);
	if (s == NULL)
		close(fd);
	return s;
}

static inline void send_to(int fd, int family, const char *ip, uint16_t port, const void *p, size_t n)
{
	struct sockaddr_storage ss;
	socklen_t sl;
	to_addr(family, ip, port, &ss, &sl);
	(void)sendto(fd, p, n, 0, (struct sockaddr *)&ss, sl);
}

/* ---- tests ---- */

#endif

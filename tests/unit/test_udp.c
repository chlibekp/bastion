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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

/* Backend-parametrised: BST_TEST_BACKEND=epoll|uring (default epoll). */
static bst_backend test_backend(void)
{
	const char *b = getenv("BST_TEST_BACKEND");
	return b != NULL && strcmp(b, "uring") == 0 ? BST_BACKEND_URING : BST_BACKEND_EPOLL;
}

static bst_loop *new_loop(unsigned udp_bufs)
{
	bst_loop_cfg cfg = {.backend = test_backend(), .uring_udp_bufs = udp_bufs};
	bst_err err;
	return bst_loop_new(&cfg, &err);
}

#define LOOP(l) bst_loop *l = new_loop(64); ASSERT(l != NULL)

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

/* ---- sockets ---- */

static int usock(int family, uint16_t *port, const char *ip)
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

static void to_addr(int family, const char *ip, uint16_t port, struct sockaddr_storage *ss,
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

static bst_sockaddr bsa(int family, const char *ip, uint16_t port)
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

static unsigned char pat(unsigned seed, size_t i)
{
	return (unsigned char)((seed * 131u) ^ (i * 7u) ^ (i >> 5));
}

static void fill(unsigned char *p, size_t n, unsigned seed)
{
	for (size_t i = 0; i < n; i++)
		p[i] = pat(seed, i);
}

static bool check(const unsigned char *p, size_t n, unsigned seed)
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

static void on_rx(void *ud, bst_udp_msg *m, int n, int err)
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

static void rx_free(rx *x)
{
	for (int i = 0; i < x->n; i++) {
		free(x->r[i].p);
		bst_buf_unref(x->r[i].m.buf);
	}
	x->n = 0;
}

static void rx_wait(rx *x, int want, uint64_t ms)
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

static void on_done(void *ud, size_t bytes, int err)
{
	sd *d = ud;
	d->calls++;
	d->bytes = bytes;
	d->err = err;
	bst_loop_stop(d->l);
}

static void sd_wait(sd *d, uint64_t ms)
{
	if (d->calls == 0)
		run_for(d->l, ms);
}

/* a bound UDP socket wrapped on the loop, with its port */
static bst_sock *wrap(bst_loop *l, int family, const char *ip, uint16_t *port)
{
	int fd = usock(family, port, ip);
	if (fd < 0)
		return NULL;
	bst_sock *s = bst_sock_wrap(l, fd);
	if (s == NULL)
		close(fd);
	return s;
}

static void send_to(int fd, int family, const char *ip, uint16_t port, const void *p, size_t n)
{
	struct sockaddr_storage ss;
	socklen_t sl;
	to_addr(family, ip, port, &ss, &sl);
	(void)sendto(fd, p, n, 0, (struct sockaddr *)&ss, sl);
}

/* ---- tests ---- */

TEST(batch_recv)
{
	LOOP(l);
	uint16_t sp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	ASSERT(s != NULL);
	static rx x;
	memset(&x, 0, sizeof x);
	x.l = l;
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), -EBUSY);
	int cl[4];
	uint16_t cp[4];
	for (int i = 0; i < 4; i++) {
		cl[i] = usock(AF_INET, &cp[i], "127.0.0.1");
		ASSERT(cl[i] >= 0);
	}
	unsigned char d[300];
	for (int k = 0; k < 16; k++)
		for (int i = 0; i < 4; i++) {
			fill(d, sizeof d, (unsigned)(i * 100 + k));
			send_to(cl[i], AF_INET, "127.0.0.1", sp, d, sizeof d - (size_t)k);
		}
	rx_wait(&x, 64, 3000);
	ASSERT_EQ(x.n, 64);
	ASSERT(x.maxn > 1);
	int per[4] = {0};
	for (int j = 0; j < x.n; j++) {
		rrec *r = &x.r[j];
		int c = -1;
		for (int i = 0; i < 4; i++)
			if (r->m.src.port == cp[i])
				c = i;
		ASSERT(c >= 0);
		ASSERT_EQ(r->m.src.ip.family, BST_IP_V4);
		ASSERT_EQ(r->m.src.ip.b[0], 127);
		ASSERT_EQ(r->m.dst.port, 0); /* ports are not part of dst */
		ASSERT_EQ(r->m.dst.ip.b[3], 1);
		int k = per[c]++;
		ASSERT_EQ((int)r->len, 300 - k); /* per-source order is kept */
		ASSERT(check(r->p, r->len, (unsigned)(c * 100 + k)));
		ASSERT_EQ(r->m.gro_segment_size, 0);
		ASSERT_EQ(r->m.ecn, 0);
	}
	bst_udp_stats st;
	bst_udp_stats_get(s, &st);
	ASSERT_EQ(st.rx_dgrams, 64);
	ASSERT_EQ(st.ring, test_backend() == BST_BACKEND_URING);
	rx_free(&x);
	for (int i = 0; i < 4; i++)
		close(cl[i]);
	bst_sock_close(s);
	bst_loop_free(l);
}

/* io_uring without multishot RECVMSG (or without UDP slots) runs UDP on readiness. */
TEST(batch_recv_without_ring)
{
	if (test_backend() != BST_BACKEND_URING) {
		printf("# skipped: epoll has no ring path\n");
		return;
	}
	bst_test_uring_nofeat = BST_URF_RECV_MSHOT;
	bst_loop *l = new_loop(64);
	bst_test_uring_nofeat = 0;
	ASSERT(l != NULL);
	uint16_t sp, cp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && c >= 0);
	static rx x;
	memset(&x, 0, sizeof x);
	x.l = l;
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	unsigned char d[100];
	for (int k = 0; k < 20; k++) {
		fill(d, sizeof d, (unsigned)k);
		send_to(c, AF_INET, "127.0.0.1", sp, d, sizeof d);
	}
	rx_wait(&x, 20, 3000);
	ASSERT_EQ(x.n, 20);
	bst_udp_stats st;
	bst_udp_stats_get(s, &st);
	ASSERT_EQ(st.ring, 0);
	for (int k = 0; k < 20; k++)
		ASSERT(check(x.r[k].p, x.r[k].len, (unsigned)k));
	rx_free(&x);
	close(c);
	bst_sock_close(s);
	bst_loop_free(l);
	/* and with no UDP slots configured at all */
	l = new_loop(0);
	ASSERT(l != NULL);
	s = wrap(l, AF_INET, "127.0.0.1", &sp);
	ASSERT(s != NULL);
	memset(&x, 0, sizeof x);
	x.l = l;
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	bst_udp_stats_get(s, &st);
	ASSERT_EQ(st.ring, 0);
	bst_sock_close(s);
	bst_loop_free(l);
}

TEST(segment_walk)
{
	bst_buf *b = bst_buf_new(3000);
	ASSERT(b != NULL);
	b->len = 3000;
	bst_udp_msg m = {.buf = b, .gro_segment_size = 1200};
	size_t off = 0, n, tot = 0;
	const unsigned char *seg;
	size_t lens[8], k = 0;
	while ((n = bst_udp_segment(&m, &off, &seg)) != 0 && k < 8) {
		ASSERT(seg == b->data + tot);
		lens[k++] = n;
		tot += n;
	}
	ASSERT_EQ(k, 3);
	ASSERT_EQ(lens[0], 1200);
	ASSERT_EQ(lens[1], 1200);
	ASSERT_EQ(lens[2], 600);
	ASSERT_EQ(tot, 3000);
	/* size 0, and a size at or above the length, are one segment */
	for (unsigned gs = 0; gs <= 3500; gs += 3000) {
		m.gro_segment_size = (uint16_t)gs;
		off = 0;
		ASSERT_EQ(bst_udp_segment(&m, &off, &seg), 3000);
		ASSERT_EQ(bst_udp_segment(&m, &off, &seg), 0);
	}
	m.gro_segment_size = 1;
	off = 0;
	for (int i = 0; i < 3000; i++)
		ASSERT_EQ(bst_udp_segment(&m, &off, &seg), 1);
	ASSERT_EQ(bst_udp_segment(&m, &off, &seg), 0);
	bst_buf_unref(b);
}

TEST(gro_split)
{
	LOOP(l);
	uint16_t sp, cp;
	bst_udp_cfg cfg = {.gro = true};
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && c >= 0);
	static rx x;
	memset(&x, 0, sizeof x);
	x.l = l;
	ASSERT_EQ(bst_udp_start(s, &cfg, on_rx, &x), 0);
	bst_udp_stats st;
	bst_udp_stats_get(s, &st);
	ASSERT_EQ(st.gro, 1);
	/* GSO sends of 10 x 1200 bytes: a GRO receiver sees them coalesced, or as plain
	 * datagrams; either way the segments are 1200 bytes each, in order */
	static unsigned char big[12000];
	struct sockaddr_storage ss;
	socklen_t sl;
	to_addr(AF_INET, "127.0.0.1", sp, &ss, &sl);
	for (int round = 0; round < 3; round++) {
		for (int i = 0; i < 10; i++)
			fill(big + i * 1200, 1200, (unsigned)(round * 10 + i));
		struct iovec iov = {.iov_base = big, .iov_len = sizeof big};
		char ctl[CMSG_SPACE(sizeof(uint16_t))] = {0};
		struct msghdr mh = {.msg_name = &ss, .msg_namelen = sl, .msg_iov = &iov, .msg_iovlen = 1,
				    .msg_control = ctl, .msg_controllen = sizeof ctl};
		struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
		cm->cmsg_level = SOL_UDP;
		cm->cmsg_type = UDP_SEGMENT;
		cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
		uint16_t gs = 1200;
		memcpy(CMSG_DATA(cm), &gs, sizeof gs);
		ASSERT(sendmsg(c, &mh, 0) == (ssize_t)sizeof big);
	}
	/* wait for everything: count segments, not messages */
	int segs = 0;
	for (int tries = 0; tries < 50 && segs < 30; tries++) {
		run_for(l, 20);
		segs = 0;
		for (int j = 0; j < x.n; j++) {
			size_t off = 0, n;
			const unsigned char *p;
			rrec *r = &x.r[j];
			bst_buf tmp = {.data = r->p, .len = r->len};
			bst_udp_msg m = r->m;
			m.buf = &tmp;
			while ((n = bst_udp_segment(&m, &off, &p)) != 0)
				segs++;
		}
	}
	ASSERT_EQ(segs, 30);
	int coalesced = 0, k = 0;
	for (int j = 0; j < x.n; j++) {
		rrec *r = &x.r[j];
		if (r->m.gro_segment_size != 0) {
			coalesced++;
			ASSERT_EQ(r->m.gro_segment_size, 1200);
			ASSERT(r->len > 1200);
		}
		bst_buf tmp = {.data = r->p, .len = r->len};
		bst_udp_msg m = r->m;
		m.buf = &tmp;
		size_t off = 0, n;
		const unsigned char *p;
		while ((n = bst_udp_segment(&m, &off, &p)) != 0) {
			ASSERT_EQ(n, 1200);
			ASSERT(check(p, n, (unsigned)k));
			k++;
		}
	}
	ASSERT_EQ(k, 30);
	printf("# gro: %d of %d messages coalesced\n", coalesced, x.n);
	ASSERT(coalesced > 0);
	rx_free(&x);
	close(c);
	bst_sock_close(s);
	bst_loop_free(l);
}

TEST(gso_send)
{
	LOOP(l);
	uint16_t sp, pp;
	bst_udp_cfg cfg = {.gso = true};
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int peer = usock(AF_INET, &pp, "127.0.0.1");
	ASSERT(s != NULL && peer >= 0);
	rx x = {.l = l};
	ASSERT_EQ(bst_udp_start(s, &cfg, on_rx, &x), 0);
	bst_udp_stats st;
	bst_udp_stats_get(s, &st);
	ASSERT_EQ(st.gso, 1);
	static unsigned char data[12000];
	for (int i = 0; i < 10; i++)
		fill(data + i * 1200, 1200, (unsigned)i);
	bst_udp_pkt p = {.data = data, .len = sizeof data, .gso_size = 1200,
			 .dst = bsa(AF_INET, "127.0.0.1", pp)};
	sd d = {.l = l};
	ASSERT_EQ(bst_udp_send(s, &p, 1, on_done, &d), 0);
	ASSERT_EQ(d.calls, 0); /* never from inside the call */
	sd_wait(&d, 3000);
	ASSERT_EQ(d.calls, 1);
	ASSERT_EQ(d.err, 0);
	ASSERT_EQ(d.bytes, sizeof data);
	unsigned char buf[2000];
	for (int i = 0; i < 10; i++) {
		struct sockaddr_in from;
		socklen_t fl = sizeof from;
		ssize_t n = recvfrom(peer, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
		ASSERT_EQ(n, 1200);
		ASSERT_EQ(ntohs(from.sin_port), sp);
		ASSERT(check(buf, 1200, (unsigned)i));
	}
	ASSERT(recv(peer, buf, sizeof buf, MSG_DONTWAIT) < 0); /* exactly 10 */
	bst_udp_stats_get(s, &st);
	ASSERT_EQ(st.tx_gso_msgs, 1);
	ASSERT_EQ(st.tx_msgs, 1);
	/* GSO off in cfg: the same packet goes as 10 plain datagrams */
	bst_sock *s2 = wrap(l, AF_INET, "127.0.0.1", &sp);
	ASSERT(s2 != NULL);
	rx x2 = {.l = l};
	ASSERT_EQ(bst_udp_start(s2, NULL, on_rx, &x2), 0);
	d.calls = 0;
	ASSERT_EQ(bst_udp_send(s2, &p, 1, on_done, &d), 0);
	sd_wait(&d, 3000);
	ASSERT_EQ(d.err, 0);
	ASSERT_EQ(d.bytes, sizeof data);
	for (int i = 0; i < 10; i++) {
		ASSERT_EQ(recv(peer, buf, sizeof buf, 0), 1200);
		ASSERT(check(buf, 1200, (unsigned)i));
	}
	bst_udp_stats_get(s2, &st);
	ASSERT_EQ(st.tx_gso_msgs, 0);
	ASSERT_EQ(st.tx_msgs, 10);
	close(peer);
	bst_sock_close(s);
	bst_sock_close(s2);
	bst_loop_free(l);
}

TEST(gso_unsupported_fallback)
{
	LOOP(l);
	uint16_t sp, pp;
	bst_udp_cfg cfg = {.gso = true};
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int peer = usock(AF_INET, &pp, "127.0.0.1");
	ASSERT(s != NULL && peer >= 0);
	rx x = {.l = l};
	ASSERT_EQ(bst_udp_start(s, &cfg, on_rx, &x), 0);
	static unsigned char a[500], b[4000], c[3000];
	fill(a, sizeof a, 1);
	fill(b, sizeof b, 2);
	fill(c, sizeof c, 3);
	bst_sockaddr to = bsa(AF_INET, "127.0.0.1", pp);
	bst_udp_pkt p[3] = {{.data = a, .len = sizeof a, .dst = to},
			    {.data = b, .len = sizeof b, .gso_size = 1000, .dst = to},
			    {.data = c, .len = sizeof c, .gso_size = 1000, .dst = to}};
	bst_test_udp_gso_eio = 1;
	sd d = {.l = l};
	ASSERT_EQ(bst_udp_send(s, p, 3, on_done, &d), 0);
	sd_wait(&d, 3000);
	ASSERT_EQ(d.calls, 1);
	ASSERT_EQ(d.err, 0);
	ASSERT_EQ(d.bytes, sizeof a + sizeof b + sizeof c);
	ASSERT_EQ(bst_test_udp_gso_eio, 0); /* the EIO was consumed */
	/* each datagram exactly once, in order: a, b in 4, c in 3 */
	unsigned char buf[2000];
	ASSERT_EQ(recv(peer, buf, sizeof buf, 0), 500);
	ASSERT(check(buf, 500, 1));
	for (int i = 0; i < 4; i++) {
		ASSERT_EQ(recv(peer, buf, sizeof buf, 0), 1000);
		ASSERT(memcmp(buf, b + i * 1000, 1000) == 0);
	}
	for (int i = 0; i < 3; i++) {
		ASSERT_EQ(recv(peer, buf, sizeof buf, 0), 1000);
		ASSERT(memcmp(buf, c + i * 1000, 1000) == 0);
	}
	ASSERT(recv(peer, buf, sizeof buf, MSG_DONTWAIT) < 0);
	bst_udp_stats st;
	bst_udp_stats_get(s, &st);
	ASSERT_EQ(st.gso, 0);
	ASSERT_EQ(st.gso_fallbacks, 1);
	ASSERT_EQ(st.tx_gso_msgs, 0);
	/* GSO stays off: the next send is plain datagrams */
	d.calls = 0;
	ASSERT_EQ(bst_udp_send(s, &p[1], 1, on_done, &d), 0);
	sd_wait(&d, 3000);
	ASSERT_EQ(d.err, 0);
	for (int i = 0; i < 4; i++)
		ASSERT_EQ(recv(peer, buf, sizeof buf, 0), 1000);
	bst_udp_stats_get(s, &st);
	ASSERT_EQ(st.tx_gso_msgs, 0);
	close(peer);
	bst_sock_close(s);
	bst_loop_free(l);
}

TEST(pktinfo_reply)
{
	LOOP(l);
	/* 127.0.0.2 is on lo by default: a second local address without changing the host */
	uint16_t sp, cp;
	bst_sock *s = wrap(l, AF_INET, "0.0.0.0", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && c >= 0);
	rx x = {.l = l};
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	const char *hosts[2] = {"127.0.0.2", "127.0.0.1"};
	for (int h = 0; h < 2; h++) {
		send_to(c, AF_INET, hosts[h], sp, "query", 5);
		rx_wait(&x, h + 1, 3000);
		ASSERT_EQ(x.n, h + 1);
		rrec *r = &x.r[h];
		bst_ip want = bsa(AF_INET, hosts[h], 0).ip;
		ASSERT(bst_ip_eq(&r->m.dst.ip, &want));
		ASSERT(r->m.ifindex != 0);
		bst_udp_pkt p = {.data = "reply", .len = 5, .dst = r->m.src, .src = r->m.dst.ip,
				 .src_ifindex = r->m.ifindex};
		sd d = {.l = l};
		ASSERT_EQ(bst_udp_send(s, &p, 1, on_done, &d), 0);
		sd_wait(&d, 3000);
		ASSERT_EQ(d.err, 0);
		char buf[16];
		struct sockaddr_in from;
		socklen_t fl = sizeof from;
		ASSERT_EQ(recvfrom(c, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl), 5);
		char text[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &from.sin_addr, text, sizeof text);
		ASSERT_STR(text, hosts[h]); /* the reply leaves from the address the query came to */
		ASSERT_EQ(ntohs(from.sin_port), sp);
	}
	rx_free(&x);
	close(c);
	bst_sock_close(s);
	bst_loop_free(l);
}

static void ecn_case(int family, const char *ip)
{
	bst_loop *l = new_loop(64);
	if (l == NULL) {
		tap_state.current_failed = 1;
		return;
	}
	uint16_t ap, bp;
	bst_sock *a = wrap(l, family, ip, &ap);
	bst_sock *b = wrap(l, family, ip, &bp);
	if (a == NULL || b == NULL) {
		printf("# skipped %s: cannot bind\n", ip);
		bst_loop_free(l);
		return;
	}
	rx xa = {.l = l}, xb = {.l = l};
	if (bst_udp_start(a, NULL, on_rx, &xa) != 0 || bst_udp_start(b, NULL, on_rx, &xb) != 0) {
		tap_state.current_failed = 1;
		return;
	}
	for (unsigned ecn = 0; ecn < 4; ecn++) {
		bst_udp_pkt p = {.data = "ecn", .len = 3, .dst = bsa(family, ip, bp), .ecn = (uint8_t)ecn};
		sd d = {.l = l};
		if (bst_udp_send(a, &p, 1, on_done, &d) != 0) {
			tap_state.current_failed = 1;
			return;
		}
		sd_wait(&d, 3000);
		rx_wait(&xb, (int)ecn + 1, 3000);
		if (xb.n != (int)ecn + 1 || xb.r[ecn].m.ecn != ecn) {
			printf("# %s: ecn %u arrived as %d (n=%d)\n", ip, ecn,
			       xb.n > (int)ecn ? xb.r[ecn].m.ecn : -1, xb.n);
			tap_state.current_failed = 1;
			return;
		}
	}
	/* the same through the socket option, set by a plain peer */
	int c = usock(family, &ap, ip);
	int v = 2;
	if (family == AF_INET)
		setsockopt(c, IPPROTO_IP, IP_TOS, &v, sizeof v);
	else
		setsockopt(c, IPPROTO_IPV6, IPV6_TCLASS, &v, sizeof v);
	send_to(c, family, ip, bp, "opt", 3);
	rx_wait(&xb, 5, 3000);
	if (xb.n != 5 || xb.r[4].m.ecn != 2)
		tap_state.current_failed = 1;
	close(c);
	rx_free(&xa);
	rx_free(&xb);
	bst_sock_close(a);
	bst_sock_close(b);
	bst_loop_free(l);
}

TEST(ecn_roundtrip)
{
	ecn_case(AF_INET, "127.0.0.1");
	ASSERT(!tap_state.current_failed);
	ecn_case(AF_INET6, "::1");
}

/* A v4 peer talking to a dual-stack socket: mapped addresses come out as IPv4. */
TEST(dual_stack_mapped)
{
	LOOP(l);
	uint16_t sp, cp;
	bst_sock *s = wrap(l, AF_INET6, "::", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && c >= 0);
	rx x = {.l = l};
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	int v = 2;
	setsockopt(c, IPPROTO_IP, IP_TOS, &v, sizeof v);
	send_to(c, AF_INET, "127.0.0.1", sp, "mapped", 6);
	rx_wait(&x, 1, 3000);
	ASSERT_EQ(x.n, 1);
	ASSERT_EQ(x.r[0].m.src.ip.family, BST_IP_V4);
	ASSERT_EQ(x.r[0].m.src.port, cp);
	ASSERT_EQ(x.r[0].m.dst.ip.family, BST_IP_V4);
	ASSERT_EQ(x.r[0].m.ecn, 2);
	bst_udp_pkt p = {.data = "back", .len = 4, .dst = x.r[0].m.src, .src = x.r[0].m.dst.ip, .ecn = 2};
	sd d = {.l = l};
	ASSERT_EQ(bst_udp_send(s, &p, 1, on_done, &d), 0);
	sd_wait(&d, 3000);
	ASSERT_EQ(d.err, 0);
	char buf[8];
	ASSERT_EQ(recv(c, buf, sizeof buf, 0), 4);
	rx_free(&x);
	close(c);
	bst_sock_close(s);
	bst_loop_free(l);
}

TEST(malformed_datagrams)
{
	LOOP(l);
	uint16_t sp, cp;
	bst_udp_cfg cfg = {.max_dgram = 1500};
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && c >= 0);
	static rx x;
	memset(&x, 0, sizeof x);
	x.l = l;
	ASSERT_EQ(bst_udp_start(s, &cfg, on_rx, &x), 0);
	static unsigned char big[3000];
	fill(big, sizeof big, 9);
	send_to(c, AF_INET, "127.0.0.1", sp, big, 0);    /* zero length */
	send_to(c, AF_INET, "127.0.0.1", sp, big, 1500); /* exactly the limit */
	send_to(c, AF_INET, "127.0.0.1", sp, big, 1501); /* one over */
	send_to(c, AF_INET, "127.0.0.1", sp, big, 3000); /* far over */
	send_to(c, AF_INET, "127.0.0.1", sp, big, 1);    /* and the stream goes on */
	rx_wait(&x, 2, 3000);
	run_for(l, 50);
	ASSERT_EQ(x.n, 2);
	ASSERT_EQ(x.r[0].len, 1500);
	ASSERT(check(x.r[0].p, 1500, 9));
	ASSERT_EQ(x.r[1].len, 1);
	bst_udp_stats st;
	bst_udp_stats_get(s, &st);
	ASSERT_EQ(st.rx_empty, 1);
	ASSERT_EQ(st.rx_trunc, 2);
	ASSERT_EQ(st.rx_dgrams, 2);
	rx_free(&x);
	close(c);
	bst_sock_close(s);
	bst_loop_free(l);
}

/* Control data is kernel-supplied but parsed with bounds checks: junk must not crash. */
TEST(cmsg_parse)
{
	union {
		char b[512];
		struct cmsghdr al;
	} u;
	memset(&u, 0, sizeof u);
	struct msghdr mh = {.msg_control = u.b, .msg_controllen = sizeof u.b};
	struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
	struct in_pktinfo pi = {.ipi_ifindex = 7};
	inet_pton(AF_INET, "10.1.2.3", &pi.ipi_addr);
	cm->cmsg_level = IPPROTO_IP;
	cm->cmsg_type = IP_PKTINFO;
	cm->cmsg_len = CMSG_LEN(sizeof pi);
	memcpy(CMSG_DATA(cm), &pi, sizeof pi);
	size_t used = CMSG_SPACE(sizeof pi);
	cm = (struct cmsghdr *)(u.b + used);
	cm->cmsg_level = SOL_SOCKET; /* unknown: skipped */
	cm->cmsg_type = 12345;
	cm->cmsg_len = CMSG_LEN(3);
	used += CMSG_SPACE(3);
	cm = (struct cmsghdr *)(u.b + used);
	int tos = 0x2a;
	cm->cmsg_level = IPPROTO_IP;
	cm->cmsg_type = IP_TOS;
	cm->cmsg_len = CMSG_LEN(1);
	memcpy(CMSG_DATA(cm), &tos, 1);
	used += CMSG_SPACE(1);
	cm = (struct cmsghdr *)(u.b + used);
	int gro = 1200;
	cm->cmsg_level = SOL_UDP;
	cm->cmsg_type = UDP_GRO;
	cm->cmsg_len = CMSG_LEN(sizeof gro);
	memcpy(CMSG_DATA(cm), &gro, sizeof gro);
	used += CMSG_SPACE(sizeof gro);
	bst_udp_meta m;
	ASSERT(bst_udp_parse_cmsg_(u.b, used, &m));
	ASSERT(m.has_dst);
	ASSERT_EQ(m.dst.ip.family, BST_IP_V4);
	ASSERT_EQ(m.dst.ip.b[0], 10);
	ASSERT_EQ(m.dst.ip.b[3], 3);
	ASSERT_EQ(m.ifindex, 7);
	ASSERT_EQ(m.ecn, 2); /* 0x2a & 3 */
	ASSERT_EQ(m.gro, 1200);
	/* every truncation of that buffer parses without reading past it (ASan) */
	char *exact = malloc(used);
	ASSERT(exact != NULL);
	for (size_t n = 0; n <= used; n++) {
		memcpy(exact, u.b, n);
		bst_udp_meta t;
		(void)bst_udp_parse_cmsg_(exact, n, &t);
		free(exact);
		exact = malloc(used);
		ASSERT(exact != NULL);
	}
	/* a cmsg_len that points past the buffer, and ones below the header size */
	memset(&u, 0, sizeof u);
	cm = (struct cmsghdr *)u.b;
	cm->cmsg_level = IPPROTO_IP;
	cm->cmsg_type = IP_PKTINFO;
	cm->cmsg_len = 4000;
	ASSERT(!bst_udp_parse_cmsg_(u.b, 64, &m) || !m.has_dst);
	for (size_t bad = 0; bad < sizeof(struct cmsghdr); bad += 3) {
		cm->cmsg_len = (__typeof__(cm->cmsg_len))bad;
		(void)bst_udp_parse_cmsg_(u.b, 64, &m);
	}
	/* a short IP_TOS payload and a short pktinfo are ignored */
	cm->cmsg_type = IP_TOS;
	cm->cmsg_len = CMSG_LEN(0);
	ASSERT(bst_udp_parse_cmsg_(u.b, CMSG_SPACE(0), &m));
	ASSERT_EQ(m.ecn, 0);
	cm->cmsg_type = IP_PKTINFO;
	cm->cmsg_len = CMSG_LEN(2);
	ASSERT(bst_udp_parse_cmsg_(u.b, CMSG_SPACE(2), &m));
	ASSERT(!m.has_dst);
	/* a GRO size of 0 stays 0 here; delivery turns it (and one over the length) into none */
	cm->cmsg_level = SOL_UDP;
	cm->cmsg_type = UDP_GRO;
	cm->cmsg_len = CMSG_LEN(sizeof gro);
	gro = 0;
	memcpy(CMSG_DATA(cm), &gro, sizeof gro);
	ASSERT(bst_udp_parse_cmsg_(u.b, CMSG_SPACE(sizeof gro), &m));
	ASSERT_EQ(m.gro, 0);
	free(exact);
}

/* sendmmsg/chain partial sends and a full socket: the rest goes later, in order, one done. */
TEST(partial_send_retry)
{
	LOOP(l);
	uint16_t sp, pp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int peer = usock(AF_INET, &pp, "127.0.0.1");
	ASSERT(s != NULL && peer >= 0);
	rx x = {.l = l};
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	static unsigned char data[10][200];
	bst_udp_pkt p[10];
	size_t total = 0;
	for (int i = 0; i < 10; i++) {
		fill(data[i], sizeof data[i], (unsigned)i);
		p[i] = (bst_udp_pkt){.data = data[i], .len = 100 + (size_t)i * 10,
				     .dst = bsa(AF_INET, "127.0.0.1", pp)};
		total += p[i].len;
	}
	bst_test_udp_send_limit = 3;
	bst_test_udp_eagain = 2;
	bst_test_udp_rounds = 0;
	sd d = {.l = l};
	ASSERT_EQ(bst_udp_send(s, p, 10, on_done, &d), 0);
	/* in flight: a second send is refused, and done has not run */
	ASSERT_EQ(bst_udp_send(s, p, 1, on_done, &d), -EBUSY);
	ASSERT_EQ(d.calls, 0);
	sd_wait(&d, 3000);
	ASSERT_EQ(d.calls, 1);
	ASSERT_EQ(d.err, 0);
	ASSERT_EQ(d.bytes, total);
	ASSERT(bst_test_udp_rounds >= 4); /* 10 packets, 3 per round */
	ASSERT_EQ(bst_test_udp_eagain, 0);
	run_for(l, 30);
	ASSERT_EQ(d.calls, 1); /* exactly once */
	unsigned char buf[300];
	for (int i = 0; i < 10; i++) {
		ASSERT_EQ(recv(peer, buf, sizeof buf, 0), 100 + i * 10);
		ASSERT(check(buf, p[i].len, (unsigned)i));
	}
	ASSERT(recv(peer, buf, sizeof buf, MSG_DONTWAIT) < 0);
	/* the slot is free again */
	d.calls = 0;
	ASSERT_EQ(bst_udp_send(s, p, 1, on_done, &d), 0);
	sd_wait(&d, 3000);
	ASSERT_EQ(d.calls, 1);
	bst_test_udp_send_limit = 0;
	close(peer);
	bst_sock_close(s);
	bst_loop_free(l);
}

TEST(send_error_and_args)
{
	LOOP(l);
	uint16_t sp, pp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int peer = usock(AF_INET, &pp, "127.0.0.1");
	ASSERT(s != NULL && peer >= 0);
	rx x = {.l = l};
	bst_udp_pkt ok = {.data = "hello", .len = 5, .dst = bsa(AF_INET, "127.0.0.1", pp)};
	sd d = {.l = l};
	ASSERT_EQ(bst_udp_send(s, &ok, 1, on_done, &d), -EINVAL); /* not started */
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	bst_udp_pkt bad = ok;
	bad.len = 0;
	ASSERT_EQ(bst_udp_send(s, &bad, 1, on_done, &d), -EINVAL);
	bad = ok;
	bad.ecn = 4;
	ASSERT_EQ(bst_udp_send(s, &bad, 1, on_done, &d), -EINVAL);
	bad = ok;
	bad.dst = bsa(AF_INET6, "::1", pp);
	ASSERT_EQ(bst_udp_send(s, &bad, 1, on_done, &d), -EINVAL); /* v6 dst on a v4 socket */
	bad = ok;
	bad.len = 70000;
	ASSERT_EQ(bst_udp_send(s, &bad, 1, on_done, &d), -EINVAL);
	ASSERT_EQ(bst_udp_send(s, &ok, 0, on_done, &d), -EINVAL);
	ASSERT_EQ(bst_udp_send(s, NULL, 1, on_done, &d), -EINVAL);
	ASSERT_EQ(bst_udp_send(s, &ok, 1, NULL, &d), -EINVAL);
	/* a kernel error in the middle: earlier packets are out, later ones are not sent */
	bst_udp_pkt p[3] = {ok, ok, ok};
	p[1].dst.port = 0; /* the kernel refuses port 0 */
	ASSERT_EQ(bst_udp_send(s, p, 3, on_done, &d), 0);
	sd_wait(&d, 3000);
	ASSERT_EQ(d.calls, 1);
	ASSERT_EQ(d.err, -EINVAL);
	ASSERT_EQ(d.bytes, 5);
	char buf[16];
	ASSERT_EQ(recv(peer, buf, sizeof buf, 0), 5);
	ASSERT(recv(peer, buf, sizeof buf, MSG_DONTWAIT) < 0);
	close(peer);
	bst_sock_close(s);
	bst_loop_free(l);
}

TEST(stop_and_close_are_silent)
{
	LOOP(l);
	uint16_t sp, pp, cp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int peer = usock(AF_INET, &pp, "127.0.0.1");
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && peer >= 0 && c >= 0);
	static rx x;
	memset(&x, 0, sizeof x);
	x.l = l;
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	send_to(c, AF_INET, "127.0.0.1", sp, "one", 3);
	rx_wait(&x, 1, 3000);
	ASSERT_EQ(x.n, 1);
	ASSERT_EQ(bst_udp_stop(s), 0);
	send_to(c, AF_INET, "127.0.0.1", sp, "two", 3);
	run_for(l, 50);
	ASSERT_EQ(x.n, 1); /* nothing after stop */
	/* a fresh stream after the stop. "two" may still be queued in the socket (epoll) or
	 * have been dropped by the cancelled receive (io_uring): either is allowed. */
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	send_to(c, AF_INET, "127.0.0.1", sp, "three", 5);
	run_for(l, 100);
	ASSERT(x.n >= 2 && x.n <= 3);
	ASSERT_EQ(x.r[x.n - 1].len, 5);
	int seen = x.n;
	/* close with a send in flight and the receive running: no callback of either */
	bst_udp_pkt p = {.data = "bye", .len = 3, .dst = bsa(AF_INET, "127.0.0.1", pp)};
	bst_test_udp_eagain = 1000;
	sd d = {.l = l};
	ASSERT_EQ(bst_udp_send(s, &p, 1, on_done, &d), 0);
	bst_sock_close(s);
	send_to(c, AF_INET, "127.0.0.1", sp, "late", 4);
	run_for(l, 100);
	bst_test_udp_eagain = 0;
	ASSERT_EQ(d.calls, 0);
	ASSERT_EQ(x.n, seen);
	char buf[8];
	ASSERT(recv(peer, buf, sizeof buf, MSG_DONTWAIT) < 0);
	rx_free(&x);
	close(peer);
	close(c);
	bst_loop_free(l);
}

/* Holding every received buffer on one socket never starves another socket of the loop. */
TEST(held_buffers_do_not_stall)
{
	bst_loop *l = new_loop(8); /* 8 ring slots */
	ASSERT(l != NULL);
	uint16_t ap, bp, cp;
	bst_sock *a = wrap(l, AF_INET, "127.0.0.1", &ap);
	bst_sock *b = wrap(l, AF_INET, "127.0.0.1", &bp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(a != NULL && b != NULL && c >= 0);
	static rx xa, xb;
	memset(&xa, 0, sizeof xa);
	memset(&xb, 0, sizeof xb);
	xa.l = xb.l = l;
	xa.hold = true;
	bst_udp_cfg big = {.max_dgram = 4096};
	ASSERT_EQ(bst_udp_start(a, &big, on_rx, &xa), 0);
	ASSERT_EQ(bst_udp_start(b, NULL, on_rx, &xb), 0);
	static unsigned char d[3000]; /* above BST_UDP_COPY_MAX: handed out, until the ring is pressed */
	unsigned copies0 = bst_test_uring_udp_copies;
	for (int k = 0; k < 40; k++) {
		fill(d, sizeof d, (unsigned)k);
		send_to(c, AF_INET, "127.0.0.1", ap, d, sizeof d);
	}
	rx_wait(&xa, 40, 3000);
	ASSERT_EQ(xa.n, 40); /* all held: far more than the ring has slots */
	if (test_backend() == BST_BACKEND_URING)
		ASSERT(bst_test_uring_udp_copies > copies0); /* copy-out under pressure did it */
	for (int k = 0; k < 40; k++) {
		ASSERT_EQ(xa.r[k].m.buf->len, sizeof d);
		ASSERT(check(xa.r[k].m.buf->data, sizeof d, (unsigned)k));
	}
	for (int k = 0; k < 5; k++)
		send_to(c, AF_INET, "127.0.0.1", bp, "b", 1);
	rx_wait(&xb, 5, 3000);
	ASSERT_EQ(xb.n, 5);
	rx_free(&xa);
	rx_free(&xb);
	close(c);
	bst_sock_close(a);
	bst_sock_close(b);
	bst_loop_free(l);
}

/* More datagrams queued than one dispatch or wakeup may take: the rest follows, in order. */
TEST(flood_budget)
{
	LOOP(l);
	uint16_t sp, cp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && c >= 0);
	static rx x;
	memset(&x, 0, sizeof x);
	x.l = l;
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	unsigned char d[20];
	int sent = 0;
	bst_test_udp_budget = 16;
	for (int k = 0; k < 150; k++) { /* queued before the loop runs: far over the budget */
		memset(d, 0, sizeof d);
		memcpy(d, &k, sizeof k);
		send_to(c, AF_INET, "127.0.0.1", sp, d, sizeof d);
		sent++;
	}
	unsigned carries0 = bst_test_uring_udp_carries;
	run_for(l, 200);
	if (test_backend() == BST_BACKEND_URING)
		ASSERT(bst_test_uring_udp_carries > carries0); /* the carry path ran */
	bst_test_udp_budget = 0;
	ASSERT_EQ(x.n, 150);
	int prev = -1;
	for (int j = 0; j < x.n; j++) {
		int k;
		ASSERT_EQ(x.r[j].len, sizeof d);
		memcpy(&k, x.r[j].p, sizeof k);
		ASSERT(k > prev); /* in order, none twice */
		prev = k;
	}
	ASSERT(sent == 150);
	rx_free(&x);
	close(c);
	bst_sock_close(s);
	bst_loop_free(l);
}

TEST(large_datagram_held)
{
	/* a datagram above the copy threshold is handed as is (a ring slot on io_uring) */
	bst_loop *l = new_loop(8);
	ASSERT(l != NULL);
	uint16_t sp, cp;
	bst_udp_cfg cfg = {.gro = true};
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && c >= 0);
	static rx x;
	memset(&x, 0, sizeof x);
	x.l = l;
	x.hold = true;
	ASSERT_EQ(bst_udp_start(s, &cfg, on_rx, &x), 0);
	static unsigned char d[60000];
	for (int k = 0; k < 20; k++) { /* more than 8 slots: pressure copies out */
		fill(d, sizeof d, (unsigned)k);
		send_to(c, AF_INET, "127.0.0.1", sp, d, sizeof d);
		run_for(l, 3); /* paced: 60 KB datagrams overrun the socket queue otherwise */
	}
	rx_wait(&x, 20, 3000);
	ASSERT_EQ(x.n, 20);
	for (int k = 0; k < x.n; k++) {
		ASSERT_EQ(x.r[k].m.buf->len, sizeof d);
		ASSERT(x.r[k].m.gro_segment_size == 0);
		ASSERT(check(x.r[k].m.buf->data, sizeof d, (unsigned)k));
	}
	rx_free(&x);
	close(c);
	bst_sock_close(s);
	bst_loop_free(l);
}

TAP_MAIN()

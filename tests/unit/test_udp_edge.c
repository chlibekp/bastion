#include "udp_test.h"

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

/* Carried over the budget with the ring pressed, the copy-out fails: the record stays in its
 * slot, flagged, and is delivered from there. Nothing is lost or doubled. */
TEST(carry_copy_failure_keeps_the_record)
{
	if (test_backend() != BST_BACKEND_URING)
		return;
	bst_loop *l = new_loop(16);
	ASSERT(l != NULL);
	uint16_t sp, cp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && c >= 0);
	static rx x;
	memset(&x, 0, sizeof x);
	x.l = l;
	x.hold = true;
	bst_udp_cfg big = {.max_dgram = 4096};
	ASSERT_EQ(bst_udp_start(s, &big, on_rx, &x), 0);
	static unsigned char d[3000]; /* above BST_UDP_COPY_MAX: each one holds a slot */
	bst_test_udp_budget = 2;
	bst_test_uring_copy_fail = 1000;
	unsigned carries0 = bst_test_uring_udp_carries;
	for (int k = 0; k < 14; k++) {
		fill(d, sizeof d, (unsigned)k);
		send_to(c, AF_INET, "127.0.0.1", sp, d, sizeof d);
	}
	rx_wait(&x, 14, 3000);
	bst_test_udp_budget = 0;
	ASSERT(bst_test_uring_udp_carries > carries0);
	ASSERT(bst_test_uring_copy_fail < 1000); /* a copy-out was attempted and refused */
	bst_test_uring_copy_fail = 0;
	ASSERT_EQ(x.n, 14);
	rx_free(&x);
	close(c);
	bst_sock_close(s);
	bst_loop_free(l);
}

/* The park tag is valid only while the carry it names is alive: once drained, a late arm with
 * that tag is not ours. */
TEST(park_tag_is_cleared_once_the_carry_drains)
{
	if (test_backend() != BST_BACKEND_URING)
		return;
	LOOP(l);
	uint16_t sp, cp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && c >= 0);
	static rx x;
	memset(&x, 0, sizeof x);
	x.l = l;
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	unsigned char d[20] = {0};
	bst_test_udp_budget = 16;
	for (int k = 0; k < 150; k++)
		send_to(c, AF_INET, "127.0.0.1", sp, d, sizeof d);
	unsigned carries0 = bst_test_uring_udp_carries;
	run_for(l, 200);
	bst_test_udp_budget = 0;
	ASSERT(bst_test_uring_udp_carries > carries0);
	ASSERT_EQ(x.n, 150);
	ASSERT(!s->udp->park_valid);
	rx_free(&x);
	close(c);
	bst_sock_close(s);
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


/* ---- io_uring record handling, by injected completions ---- */

#define POFF (sizeof(struct io_uring_recvmsg_out) + BST_UDP_RNAME + BST_UDP_CTL)

/* A RECVMSG record as the kernel writes it, from 10.0.0.9:4242. */
static bst_buf *mkrec(size_t plen, unsigned flags, unsigned controllen, const void *ctl,
		      size_t ctllen, int family)
{
	size_t total = POFF + plen;
	bst_buf *b = bst_buf_new(total);
	if (b == NULL)
		return NULL;
	memset(b->data, 0, total);
	struct io_uring_recvmsg_out o = {.namelen = sizeof(struct sockaddr_in), .controllen = controllen,
					 .payloadlen = (unsigned)plen, .flags = flags};
	memcpy(b->data, &o, sizeof o);
	struct sockaddr_in sa = {.sin_family = (sa_family_t)family, .sin_port = htons(4242)};
	inet_pton(AF_INET, "10.0.0.9", &sa.sin_addr);
	memcpy(b->data + sizeof o, &sa, sizeof sa);
	if (ctl != NULL)
		memcpy(b->data + sizeof o + BST_UDP_RNAME, ctl, ctllen);
	fill(b->data + POFF, plen, 5);
	b->len = total;
	return b;
}

static size_t gro_ctl(unsigned char *out, int gro)
{
	memset(out, 0, 64);
	struct cmsghdr *cm = (struct cmsghdr *)out;
	cm->cmsg_level = SOL_UDP;
	cm->cmsg_type = UDP_GRO;
	cm->cmsg_len = CMSG_LEN(sizeof gro);
	memcpy(CMSG_DATA(cm), &gro, sizeof gro);
	return CMSG_SPACE(sizeof gro);
}

static bool ring_loop(bst_loop **l, bst_sock **s, rx *x)
{
	if (test_backend() != BST_BACKEND_URING) {
		printf("# skipped: injected completions are io_uring's\n");
		return false;
	}
	*l = new_loop(64);
	uint16_t sp;
	*s = *l != NULL ? wrap(*l, AF_INET, "127.0.0.1", &sp) : NULL;
	memset(x, 0, sizeof *x);
	x->l = *l;
	return *s != NULL && bst_udp_start(*s, NULL, on_rx, x) == 0;
}

TEST(ring_record_handling)
{
	static rx x;
	bst_loop *l;
	bst_sock *s;
	if (test_backend() != BST_BACKEND_URING) {
		printf("# skipped: injected completions are io_uring's\n");
		return;
	}
	ASSERT(ring_loop(&l, &s, &x));
	bst_udp_stats st, st0;
	uint16_t tag = s->u.r_tag;
	unsigned char ctl[64];
	/* a good one: source, payload */
	bst_test_uring_udp_inject(s, (int)(POFF + 100), mkrec(100, 0, 0, NULL, 0, AF_INET), tag, false);
	ASSERT_EQ(x.n, 1);
	ASSERT_EQ(x.r[0].len, 100);
	ASSERT_EQ(x.r[0].m.src.port, 4242);
	ASSERT_EQ(x.r[0].m.src.ip.b[0], 10);
	ASSERT(check(x.r[0].p, 100, 5));
	bst_udp_stats_get(s, &st0);
	struct {
		const char *what;
		size_t res;
		bst_buf *rec;
		int d_empty, d_trunc, d_badctl;
	} bad[] = {
		{"zero payload", POFF, mkrec(0, 0, 0, NULL, 0, AF_INET), 1, 0, 0},
		{"MSG_TRUNC", POFF + 100, mkrec(100, MSG_TRUNC, 0, NULL, 0, AF_INET), 0, 1, 0},
		{"over the limit", POFF + 2049, mkrec(2049, 0, 0, NULL, 0, AF_INET), 0, 1, 0},
		{"MSG_CTRUNC", POFF + 100, mkrec(100, MSG_CTRUNC, 0, NULL, 0, AF_INET), 0, 0, 1},
		{"controllen over the space", POFF + 100, mkrec(100, 0, BST_UDP_CTL + 1, NULL, 0, AF_INET), 0, 0, 1},
		{"name not IP", POFF + 100, mkrec(100, 0, 0, NULL, 0, AF_UNSPEC), 0, 0, 1},
		{"record shorter than its header", POFF - 1, mkrec(10, 0, 0, NULL, 0, AF_INET), 0, 0, 1},
		{"malformed control", POFF + 100, mkrec(100, 0, 4, "\xff\xff\xff\xff", 4, AF_INET), 0, 0, 1},
	};
	for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		ASSERT(bad[i].rec != NULL);
		bst_udp_stats_get(s, &st);
		bst_test_uring_udp_inject(s, (int)bad[i].res, bad[i].rec, tag, false);
		bst_udp_stats_get(s, &st0);
		if (x.n != 1 || (int)(st0.rx_empty - st.rx_empty) != bad[i].d_empty ||
		    (int)(st0.rx_trunc - st.rx_trunc) != bad[i].d_trunc ||
		    (int)(st0.rx_badctl - st.rx_badctl) != bad[i].d_badctl)
			TAP_FAIL_("%s: n=%d empty+%d trunc+%d badctl+%d", bad[i].what, x.n,
				  (int)(st0.rx_empty - st.rx_empty), (int)(st0.rx_trunc - st.rx_trunc),
				  (int)(st0.rx_badctl - st.rx_badctl));
	}
	/* a payload of exactly the limit is delivered whole */
	bst_test_uring_udp_inject(s, (int)(POFF + 2048), mkrec(2048, 0, 0, NULL, 0, AF_INET), tag, false);
	ASSERT_EQ(x.n, 2);
	ASSERT_EQ(x.r[1].len, 2048);
	/* GRO size equal to the length is no coalescing; one below it is kept */
	size_t cl = gro_ctl(ctl, 300);
	bst_test_uring_udp_inject(s, (int)(POFF + 300), mkrec(300, 0, (unsigned)cl, ctl, cl, AF_INET), tag, false);
	cl = gro_ctl(ctl, 299);
	bst_test_uring_udp_inject(s, (int)(POFF + 300), mkrec(300, 0, (unsigned)cl, ctl, cl, AF_INET), tag, false);
	cl = gro_ctl(ctl, 0);
	bst_test_uring_udp_inject(s, (int)(POFF + 300), mkrec(300, 0, (unsigned)cl, ctl, cl, AF_INET), tag, false);
	ASSERT_EQ(x.n, 5);
	ASSERT_EQ(x.r[2].m.gro_segment_size, 0);
	ASSERT_EQ(x.r[3].m.gro_segment_size, 299);
	ASSERT_EQ(x.r[4].m.gro_segment_size, 0);
	rx_free(&x);
	bst_sock_close(s);
	bst_loop_free(l);
}

/* A completion of an arm that stop or a restart retired is dropped: its data never reaches
 * the new callback, and its error never ends the new stream. */
TEST(stale_completions_dropped)
{
	static rx x;
	bst_loop *l;
	bst_sock *s;
	if (test_backend() != BST_BACKEND_URING) {
		printf("# skipped: injected completions are io_uring's\n");
		return;
	}
	ASSERT(ring_loop(&l, &s, &x));
	uint16_t old = s->u.r_tag;
	ASSERT_EQ(bst_udp_stop(s), 0);
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	uint16_t cur = s->u.r_tag;
	ASSERT(old != cur);
	bst_test_uring_udp_inject(s, (int)(POFF + 50), mkrec(50, 0, 0, NULL, 0, AF_INET), old, false);
	ASSERT_EQ(x.n, 0); /* old data: dropped */
	bst_test_uring_udp_inject(s, -ECONNRESET, NULL, old, true);
	bst_test_uring_udp_inject(s, -EIO, NULL, old, true);
	ASSERT_EQ(x.err, 0); /* old errors: ignored */
	bst_test_uring_udp_inject(s, (int)(POFF + 60), mkrec(60, 0, 0, NULL, 0, AF_INET), cur, false);
	ASSERT_EQ(x.n, 1); /* the live arm still delivers */
	uint16_t sp;
	struct sockaddr_in a;
	socklen_t al = sizeof a;
	getsockname(s->fd, (struct sockaddr *)&a, &al);
	sp = ntohs(a.sin_port);
	uint16_t cp;
	int c = usock(AF_INET, &cp, "127.0.0.1");
	run_for(l, 30); /* the stop, the cancel and the new arm are submitted and settled */
	send_to(c, AF_INET, "127.0.0.1", sp, "real", 4);
	rx_wait(&x, 2, 3000);
	ASSERT_EQ(x.n, 2);
	ASSERT_EQ(x.err, 0);
	rx_free(&x);
	close(c);
	bst_sock_close(s);
	bst_loop_free(l);
}

/* ---- control data truncation, ICMP errors, slot exhaustion ---- */

TEST(control_truncated_dropped)
{
	LOOP(l);
	uint16_t sp, cp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && c >= 0);
	rx x = {.l = l};
	bst_test_udp_ctl_cap = 8; /* less than one cmsg: the kernel sets MSG_CTRUNC */
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	send_to(c, AF_INET, "127.0.0.1", sp, "data", 4);
	run_for(l, 100);
	bst_test_udp_ctl_cap = 0;
	bst_udp_stats st;
	bst_udp_stats_get(s, &st);
	ASSERT_EQ(x.n, 0); /* never delivered with metadata missing */
	ASSERT_EQ(st.rx_badctl, 1);
	rx_free(&x);
	close(c);
	bst_sock_close(s);
	bst_loop_free(l);
}

/* ICMP errors on a connected socket are not stream errors: the stream goes on. */
TEST(icmp_error_is_not_fatal)
{
	LOOP(l);
	uint16_t mp, bp;
	int m = usock(AF_INET, &mp, "127.0.0.1");
	int b = usock(AF_INET, &bp, "127.0.0.1");
	ASSERT(m >= 0 && b >= 0);
	struct sockaddr_storage ss;
	socklen_t sl;
	to_addr(AF_INET, "127.0.0.1", bp, &ss, &sl);
	ASSERT_EQ(connect(m, (struct sockaddr *)&ss, sl), 0);
	close(b); /* nobody listens there now */
	ASSERT_EQ(send(m, "x", 1, 0), 1);
	usleep(20000); /* the port-unreachable comes back: ECONNREFUSED is pending on m */
	bst_sock *s = bst_sock_wrap(l, m);
	ASSERT(s != NULL);
	rx x = {.l = l};
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	/* the connected peer comes back on the same port and sends */
	struct sockaddr_in ba = {.sin_family = AF_INET, .sin_port = htons(bp)};
	inet_pton(AF_INET, "127.0.0.1", &ba.sin_addr);
	int b2 = socket(AF_INET, SOCK_DGRAM, 0);
	ASSERT(bind(b2, (struct sockaddr *)&ba, sizeof ba) == 0);
	send_to(b2, AF_INET, "127.0.0.1", mp, "alive", 5);
	rx_wait(&x, 1, 3000);
	ASSERT_EQ(x.err, 0);
	ASSERT_EQ(x.n, 1);
	ASSERT_EQ(x.r[0].len, 5);
	rx_free(&x);
	close(b2);
	bst_sock_close(s);
	bst_loop_free(l);
}

/* More datagrams than UDP slots: the kernel ends the multishot with -ENOBUFS, it is re-armed
 * once slots are back, and the datagrams still queued in the socket arrive. */
TEST(slots_exhausted_rearm)
{
	if (test_backend() != BST_BACKEND_URING) {
		printf("# skipped: slots are io_uring's\n");
		return;
	}
	bst_loop *l = new_loop(2);
	ASSERT(l != NULL);
	uint16_t sp, cp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	ASSERT(s != NULL && c >= 0);
	static rx x;
	memset(&x, 0, sizeof x);
	x.l = l;
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	unsigned nb0 = bst_test_uring_udp_nobufs;
	for (int k = 0; k < 12; k++)
		send_to(c, AF_INET, "127.0.0.1", sp, &k, sizeof k);
	rx_wait(&x, 12, 3000);
	ASSERT_EQ(x.n, 12);
	ASSERT(bst_test_uring_udp_nobufs > nb0);
	for (int k = 0; k < 12; k++) {
		int v;
		memcpy(&v, x.r[k].p, sizeof v);
		ASSERT_EQ(v, k);
	}
	rx_free(&x);
	close(c);
	bst_sock_close(s);
	bst_loop_free(l);
}

/* ---- fairness ---- */

static rx fair_udp;
static int fair_at = -1;

static void on_tcp_data(void *ud, bst_buf *d, int err)
{
	(void)ud, (void)err;
	if (d != NULL && fair_at < 0)
		fair_at = fair_udp.n;
	bst_buf_unref(d);
}

/* A flooded UDP socket and a neighbour stream socket on one loop: the neighbour is served
 * after at most the UDP budget of datagrams, and every datagram still arrives, in order. */
TEST(flood_does_not_starve_neighbour)
{
	LOOP(l);
	uint16_t sp, cp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int c = usock(AF_INET, &cp, "127.0.0.1");
	int sv[2];
	ASSERT(s != NULL && c >= 0);
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	bst_sock *t = bst_sock_wrap(l, sv[0]);
	ASSERT(t != NULL);
	memset(&fair_udp, 0, sizeof fair_udp);
	fair_udp.l = l;
	fair_at = -1;
	bst_test_udp_budget = 16;
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &fair_udp), 0);
	ASSERT_EQ(bst_io_recv_start(t, on_tcp_data, NULL), 0);
	for (int k = 0; k < 150; k++)
		send_to(c, AF_INET, "127.0.0.1", sp, &k, sizeof k);
	ASSERT_EQ(write(sv[1], "hello", 5), 5);
	run_for(l, 300);
	bst_test_udp_budget = 0;
	ASSERT(fair_at >= 0); /* the neighbour was served */
	ASSERT(fair_at <= 16); /* after at most one budget of datagrams */
	ASSERT_EQ(fair_udp.n, 150);
	for (int k = 0; k < 150; k++) {
		int v;
		memcpy(&v, fair_udp.r[k].p, sizeof v);
		ASSERT_EQ(v, k);
	}
	rx_free(&fair_udp);
	close(c);
	close(sv[1]);
	bst_sock_close(t);
	bst_sock_close(s);
	bst_loop_free(l);
}

TAP_MAIN()

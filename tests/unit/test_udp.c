#include "udp_test.h"

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
	if (coalesced == 0) /* the segment order above is checked either way */
		printf("# skip: this kernel does not coalesce on loopback; coalescing not checked\n");
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

TAP_MAIN()

/* A GSO send of exactly 64 segments goes out; 65 is refused, whatever the remainder. */
TEST(gso_segment_limit)
{
	LOOP(l);
	uint16_t sp, pp;
	bst_udp_cfg cfg = {.gso = true};
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int peer = usock(AF_INET, &pp, "127.0.0.1");
	ASSERT(s != NULL && peer >= 0);
	int rb = 1 << 20;
	setsockopt(peer, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
	rx x = {.l = l};
	ASSERT_EQ(bst_udp_start(s, &cfg, on_rx, &x), 0);
	static unsigned char data[6600];
	for (int i = 0; i < 66; i++)
		fill(data + i * 100, 100, (unsigned)i);
	bst_udp_pkt p = {.data = data, .len = 6400, .gso_size = 100, .dst = bsa(AF_INET, "127.0.0.1", pp)};
	sd d = {.l = l};
	ASSERT_EQ(bst_udp_send(s, &p, 1, on_done, &d), 0);
	sd_wait(&d, 3000);
	ASSERT_EQ(d.err, 0);
	ASSERT_EQ(d.bytes, 6400);
	unsigned char buf[200];
	for (int i = 0; i < 64; i++) {
		ASSERT_EQ(recv(peer, buf, sizeof buf, 0), 100);
		ASSERT(check(buf, 100, (unsigned)i));
	}
	ASSERT(recv(peer, buf, sizeof buf, MSG_DONTWAIT) < 0);
	p.len = 6500; /* 65 segments */
	ASSERT_EQ(bst_udp_send(s, &p, 1, on_done, &d), -EINVAL);
	p.len = 6401; /* 64 full segments and a 1-byte one: 65 */
	ASSERT_EQ(bst_udp_send(s, &p, 1, on_done, &d), -EINVAL);
	p.len = 6300; /* 63 */
	d.calls = 0;
	ASSERT_EQ(bst_udp_send(s, &p, 1, on_done, &d), 0);
	sd_wait(&d, 3000);
	ASSERT_EQ(d.bytes, 6300);
	close(peer);
	bst_sock_close(s);
	bst_loop_free(l);
}

/* The socket's DSCP is kept when a packet's ECN bits are set. */
TEST(tos_keeps_dscp)
{
	LOOP(l);
	uint16_t sp, pp;
	bst_sock *s = wrap(l, AF_INET, "127.0.0.1", &sp);
	int peer = usock(AF_INET, &pp, "127.0.0.1");
	ASSERT(s != NULL && peer >= 0);
	int ef = 0xb8, on = 1;
	ASSERT_EQ(setsockopt(s->fd, IPPROTO_IP, IP_TOS, &ef, sizeof ef), 0);
	setsockopt(peer, IPPROTO_IP, IP_RECVTOS, &on, sizeof on);
	rx x = {.l = l};
	ASSERT_EQ(bst_udp_start(s, NULL, on_rx, &x), 0);
	for (unsigned ecn = 0; ecn < 4; ecn += 2) {
		bst_udp_pkt p = {.data = "t", .len = 1, .dst = bsa(AF_INET, "127.0.0.1", pp), .ecn = (uint8_t)ecn};
		sd d = {.l = l};
		ASSERT_EQ(bst_udp_send(s, &p, 1, on_done, &d), 0);
		sd_wait(&d, 3000);
		char b[4], ctl[64];
		struct iovec iov = {.iov_base = b, .iov_len = sizeof b};
		struct msghdr mh = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctl, .msg_controllen = sizeof ctl};
		ASSERT_EQ(recvmsg(peer, &mh, 0), 1);
		int tos = -1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare" /* musl's CMSG_NXTHDR */
		for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm != NULL; cm = CMSG_NXTHDR(&mh, cm))
			if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_TOS)
				tos = *(unsigned char *)CMSG_DATA(cm);
#pragma GCC diagnostic pop
		ASSERT_EQ(tos, 0xb8 | (int)ecn); /* DSCP EF stays, ECN is the packet's */
	}
	close(peer);
	bst_sock_close(s);
	bst_loop_free(l);
}

/* GRO sizes: 0, at or above the datagram, or above a UDP payload mean one segment. */
TEST(gro_size_normalised)
{
	static const struct { uint32_t gro; size_t len; unsigned want; } c[] = {
		{0, 3000, 0}, {1200, 3000, 1200}, {2999, 3000, 2999}, {3000, 3000, 0},
		{3001, 3000, 0}, {1, 3000, 1}, {65535, 100000, 65535}, {65536, 100000, 0},
	};
	for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
		bst_udp_meta meta = {.gro = c[i].gro};
		bst_udp_msg m;
		memset(&m, 0, sizeof m);
		bst_udp_fill_msg_(&m, &meta, c[i].len);
		if (m.gro_segment_size != c[i].want)
			TAP_FAIL_("gro %u len %zu: got %u want %u", c[i].gro, c[i].len, m.gro_segment_size, c[i].want);
	}
}

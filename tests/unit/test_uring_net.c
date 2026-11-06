/* io_uring only: recv over the provided-buffer ring, sends (zero-copy, splice, sendfile
 * fallback). Runs on io_uring whatever BST_TEST_BACKEND says. */
#include "uring_util.h"

/* ---- multishot_recv_rearms ---- */

TEST(multishot_recv_rearms)
{
	/* A CQ of 4, no more than the per-dispatch budget: the kernel ends a multishot recv
	 * once the CQ is full (the budget never cancels it here), and the backend must arm it
	 * again by itself. */
	bst_test_uring_cq = 4;
	bst_loop *l = uloop((bst_loop_cfg){.uring_entries = 2});
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
	ASSERT(pre >= 8u * BST_RECV_BUF_SIZE);
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
	bst_test_uring_copies = 0;
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
	ASSERT(bst_test_uring_nobufs > 0); /* the ring really ran dry, */
	ASSERT(r.max_held > 4); /* yet the consumer held more than the ring has: copies */
	ASSERT(bst_test_uring_copies > 0);
	bst_sock_close(s);
	close(b);
	bst_loop_free(l);
}

/* ---- multishot recv ended by -ENOBUFS is re-armed ---- */

/* A burst far larger than the ring (4 slots): the kernel's multishot recv takes every slot,
 * then ends with -ENOBUFS. The backend arms it again as slots come back (copy-out returns
 * them at once), the caller never sees the error, and no byte is lost. */
TEST(multishot_recv_enobufs_rearmed)
{
	bst_loop *l = uloop((bst_loop_cfg){.uring_bufs = 4});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	int big = 1 << 20;
	setsockopt(a, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
	setsockopt(b, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
	fcntl(b, F_SETFL, O_NONBLOCK);
	size_t pre = 0;
	static unsigned char chunk[16384];
	while (pre < (256u << 10)) {
		for (size_t i = 0; i < sizeof chunk; i++)
			chunk[i] = pat(pre + i);
		ssize_t k = write(b, chunk, sizeof chunk);
		if (k <= 0)
			break;
		pre += (size_t)k;
	}
	ASSERT(pre >= 8u * BST_RECV_BUF_SIZE); /* twice the ring, queued before recv starts */
	bst_sock *s = bst_sock_wrap(l, a);
	rx r = {.l = l, .s = s, .want = pre};
	bst_test_uring_nobufs = 0;
	ASSERT_EQ(bst_io_recv_start(s, on_rx, &r), 0);
	run_until(l, &r.done, 10000);
	ASSERT(bst_test_uring_nobufs > 0); /* the multishot recv ended with -ENOBUFS, */
	ASSERT_EQ(r.got, pre);             /* and came back by itself for the rest */
	ASSERT_EQ(r.bad, 0);
	ASSERT_EQ(r.errcb, 0);
	bst_sock_close(s);
	close(b);
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
	run_for(l, 100); /* the peer reads nothing: the socket fills up */
	ASSERT_EQ(r.calls, 0);
	ASSERT(bst_test_uring_splice_outs > 0);
	bst_test_uring_splice_outs = 0;
	run_for(l, 100); /* full all along: one splice parked behind POLLOUT, at most */
	ASSERT(bst_test_uring_splice_outs <= 1);
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


/* ---- zero-copy: the chain and its buffers outlive the kernel's use of the pages ---- */

static void fill_pat(bst_buf *b, uint64_t base)
{
	for (size_t i = 0; i < b->len; i++)
		b->data[i] = pat(base + i);
}

/* A ZC round to a peer that reads nothing: the request completes but the pages stay in the
 * TCP queue, so the chain must not be consumed (its buffers would be freed under it). */
TEST(zc_chain_held_until_notification)
{
	bst_loop *l = uloop((bst_loop_cfg){.uring_send_zc_min = 4096});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	int small = 64 << 10;
	setsockopt(b, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
	size_t n = 1u << 20;
	bst_buf *buf = mem_buf(0, n);
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	ASSERT_EQ(bst_chain_add_mem(&c, buf, 0, n), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_for(l, 100); /* the peer reads nothing: the kernel holds the pages */
	ASSERT(s->u.zc_hold > 0);
	ASSERT_EQ(bst_chain_len(&c), (uint64_t)n); /* nothing consumed while the kernel uses it */
	reader rd = {.fd = b, .total = n};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, read_thread, &rd), 0);
	run_until(l, &r.done, 5000);
	pthread_join(th, NULL);
	ASSERT_EQ(r.err, 0);
	ASSERT_EQ(rd.got, n);
	ASSERT_EQ(rd.bad, 0);
	bst_buf_unref(buf);
	bst_sock_close(s);
	close(b);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* Close with ZC pages still queued; the caller then rewrites memory: its own buffer in
 * place (inplace), or frees its buffers and allocates new ones of the same size, which reuse
 * the same heap memory (realloc). The peer must never receive the rewritten bytes. */
static void zc_close_case(int inplace)
{
	bst_loop *l = uloop((bst_loop_cfg){.uring_send_zc_min = 4096});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	int small = 64 << 10;
	setsockopt(b, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
	enum { NSEG = 16, SEG = 64 << 10 }; /* heap-sized pieces (below the mmap threshold) */
	bst_buf *bufs[NSEG];
	bst_slab *slab = bst_chain_slab_new(32);
	bst_chain c;
	bst_chain_init(&c, slab);
	for (int i = 0; i < NSEG; i++) {
		bufs[i] = bst_buf_new(SEG);
		bufs[i]->len = SEG;
		fill_pat(bufs[i], (uint64_t)i * SEG);
		ASSERT_EQ(bst_chain_add_mem(&c, bufs[i], 0, SEG), 0);
	}
	bst_sock *s = bst_sock_wrap(l, a);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_for(l, 100);
	ASSERT(s->u.zc_hold > 0); /* pages still queued in TCP */
	bst_sock_close(s);
	bst_buf *again[NSEG];
	if (inplace) {
		for (int i = 0; i < NSEG; i++)
			memset(bufs[i]->data, 0xAA, SEG);
	} else {
		bst_chain_clear(&c);
		/* The backend keeps its own reference on the buffers the kernel still reads, so
		 * the caller's unref cannot free them (ASan's quarantine would hide the reuse). */
		int held = 0;
		for (int i = 0; i < NSEG; i++)
			held += bufs[i]->refs >= 2;
		ASSERT(held > 0);
		for (int i = 0; i < NSEG; i++)
			bst_buf_unref(bufs[i]);
		for (int i = 0; i < NSEG; i++) {
			again[i] = bst_buf_new(SEG);
			memset(again[i]->data, 0xAA, SEG);
		}
	}
	reader rd = {.fd = b, .total = (uint64_t)NSEG * SEG};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, read_thread, &rd), 0);
	run_for(l, 300);
	bst_loop_free(l);
	shutdown(b, SHUT_RD);
	pthread_join(th, NULL);
	printf("# zc close (%s): peer got %llu bytes\n", inplace ? "in place" : "freed, reused",
	       (unsigned long long)rd.got);
	ASSERT_EQ(rd.bad, 0); /* whatever arrived is the original bytes */
	ASSERT_EQ(r.calls, 0);
	if (inplace) {
		bst_chain_clear(&c);
		for (int i = 0; i < NSEG; i++)
			bst_buf_unref(bufs[i]);
	} else {
		for (int i = 0; i < NSEG; i++)
			bst_buf_unref(again[i]);
	}
	close(b);
	bst_slab_free(slab);
}

TEST(zc_close_never_sends_rewritten_memory)
{
	zc_close_case(0);
	zc_close_case(1);
}

/* ---- file sends: sendfile fallback, pipe pool bounds ---- */

static void file_chain(bst_chain *c, int *fds, size_t seg, int nseg, uint64_t base)
{
	for (int i = 0; i < nseg; i++) {
		fds[i] = pat_file(seg, base + (uint64_t)i * seg);
		(void)bst_chain_add_file(c, fds[i], 0, (off_t)seg);
	}
}

/* A filesystem without splice_read: SPLICE_IN fails with -EINVAL (forced here with a bad
 * flag), and the send carries on with sendfile, byte-identical. */
TEST(splice_failure_falls_back_to_sendfile)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_slab *slab = bst_chain_slab_new(8);
	bst_chain c;
	bst_chain_init(&c, slab);
	bst_buf *m = mem_buf(0, 1000);
	ASSERT_EQ(bst_chain_add_mem(&c, m, 0, 1000), 0);
	int fds[2];
	file_chain(&c, fds, 3u << 20, 2, 1000);
	uint64_t total = 1000 + 2 * (3u << 20);
	reader rd = {.fd = b, .total = total};
	pthread_t th;
	ASSERT_EQ(pthread_create(&th, NULL, read_thread, &rd), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	sendres r = {.l = l};
	bst_test_uring_splice_einval = 1;
	bst_test_uring_sendfiles = 0;
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_until(l, &r.done, 20000);
	bst_test_uring_splice_einval = 0;
	pthread_join(th, NULL);
	ASSERT_EQ(r.err, 0);
	ASSERT_EQ(r.bytes, total);
	ASSERT_EQ(rd.got, total);
	ASSERT_EQ(rd.bad, 0);
	ASSERT(bst_test_uring_sendfiles > 0);
	bst_sock_close(s);
	close(b);
	close(fds[0]);
	close(fds[1]);
	bst_buf_unref(m);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* Above the cap on pipes in use, a file send uses sendfile instead of another pipe. */
TEST(pipe_cap_falls_back_to_sendfile)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	bst_test_uring_pipes_max = 1;
	bst_test_uring_sendfiles = 0;
	bst_test_uring_pipes_made = 0;
	int a[2], b[2], fds[2][2];
	bst_slab *slab = bst_chain_slab_new(8);
	bst_chain c[2];
	bst_sock *s[2];
	sendres r[2];
	reader rd[2];
	pthread_t th[2];
	uint64_t total = 2 * (2u << 20);
	for (int i = 0; i < 2; i++) {
		ASSERT_EQ(tcp_pair(&a[i], &b[i]), 0);
		bst_chain_init(&c[i], slab);
		file_chain(&c[i], fds[i], 2u << 20, 2, 0);
		s[i] = bst_sock_wrap(l, a[i]);
		r[i] = (sendres){.l = l};
		ASSERT_EQ(bst_io_send(s[i], &c[i], on_done, &r[i]), 0);
	}
	for (int i = 0; i < 2; i++) {
		rd[i] = (reader){.fd = b[i], .total = total};
		ASSERT_EQ(pthread_create(&th[i], NULL, read_thread, &rd[i]), 0);
	}
	uint64_t end = mono_ms() + 20000;
	while ((!r[0].done || !r[1].done) && mono_ms() < end)
		run_for(l, 5);
	bst_test_uring_pipes_max = 0;
	for (int i = 0; i < 2; i++) {
		pthread_join(th[i], NULL);
		ASSERT_EQ(r[i].err, 0);
		ASSERT_EQ(rd[i].got, total);
		ASSERT_EQ(rd[i].bad, 0);
		bst_sock_close(s[i]);
		close(b[i]);
		close(fds[i][0]);
		close(fds[i][1]);
	}
	ASSERT_EQ(bst_test_uring_pipes_made, 1); /* one pipe in use at a time, at most */
	ASSERT(bst_test_uring_sendfiles > 0);     /* the other send went by sendfile */
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* Pipes are made BST_URING_PIPE_SIZE, not as large as a send chunk. */
TEST(pipe_default_size)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	bst_uring *u = l->be;
	int err = 0;
	bst_upipe *p = bst_upipe_get_(u, &err);
	ASSERT(p != NULL);
	ASSERT_EQ(p->cap, BST_URING_PIPE_SIZE);
	ASSERT_EQ(fcntl(p->wr, F_GETPIPE_SZ), (int)BST_URING_PIPE_SIZE);
	bst_upipe_put_(u, p, true);
	bst_loop_free(l);
}

TAP_MAIN()

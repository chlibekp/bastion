/* io_uring only: setup, lifetime, generations, drain, overflow, close paths, accept.
 * Runs on io_uring whatever BST_TEST_BACKEND says; test_loop, test_io_tcp and test_io_fair
 * cover the common API on both backends, test_uring_net the io_uring stream paths. */
#include "uring_util.h"

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

/* ---- close paths: no SQE for the cancel, a failed getpeername ---- */

/* The SQ is full when a socket is closed: its cancel waits on a retry list, the fd stays
 * open meanwhile (the request still names it), and both resolve at the next wait. */
TEST(cancel_without_sqe_is_retried)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	rx r = {.l = l, .s = s};
	ASSERT_EQ(bst_io_recv_start(s, on_rx, &r), 0);
	run_for(l, 10); /* the multishot recv is in the kernel */
	ASSERT(s->u.r_live);
	bst_test_uring_sqe_fail = 1; /* the cancel gets no SQE */
	bst_sock_close(s);
	bst_test_uring_sqe_fail = 0;
	ASSERT(s->fd_held);                 /* not closed under a request that names it */
	ASSERT(fcntl(a, F_GETFD) >= 0);
	ASSERT(bst_test_uring_pending_cancels(l) == 1);
	ASSERT_EQ(write(b, "late", 4), 4);  /* never delivered */
	run_for(l, 30);
	ASSERT_EQ(bst_test_uring_pending_cancels(l), 0);
	ASSERT_EQ(r.got, 0);
	ASSERT(fcntl(a, F_GETFD) < 0);      /* closed once the request was cancelled */
	int p[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
	bst_sock *s2 = bst_sock_wrap(l, p[0]);
	ASSERT(s2 == s); /* and the socket was freed */
	bst_sock_close(s2);
	close(p[1]);
	close(b);
	bst_loop_free(l);
}

/* getpeername fails (the connection reset before it was looked at): the fd is closed and
 * accepting goes on; NULL peer means non-IP and must not be passed for a TCP listener. */
TEST(accept_peer_failure_closes_fd)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	uint16_t port;
	int ls = listen_local(&port, 16);
	int c1 = client_to(port), c2 = client_to(port);
	ASSERT(c1 >= 0 && c2 >= 0);
	int before = count_open_fds();
	accres r = {.l = l, .target = 1};
	bst_test_uring_peer_fail = 1;
	ASSERT_EQ(bst_io_accept_start(l, ls, on_accept_count, &r), 0);
	run_for(l, 50);
	bst_test_uring_peer_fail = 0;
	ASSERT_EQ(r.errs, 0);
	ASSERT_EQ(r.n, 1);                   /* only the connection with a peer address */
	ASSERT_EQ(count_open_fds(), before); /* the other was closed (on_accept_count closes) */
	bst_io_accept_stop(l, ls);
	close(c1);
	close(c2);
	close(ls);
	bst_loop_free(l);
}

/* ---- Task 3 leftovers ---- */

/* A close whose cancel finds no SQE keeps the socket alive until the cancel goes in. The SQ
 * stays unavailable across a wait: the send completes meanwhile (the peer closed), and the
 * socket must NOT be freed and its slab slot reused by a new socket whose first send then
 * gets cancelled by the old, still waiting cancel. */
TEST(pending_cancel_holds_socket)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	bst_buf *big = mem_buf(0, 16u << 20);
	ASSERT_EQ(bst_chain_add_mem(&c, big, 0, 16u << 20), 0);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_for(l, 20);
	bst_test_uring_sqe_fail = 100000;
	bst_sock_close(s);
	ASSERT_EQ(bst_test_uring_pending_cancels(l), 1);
	ASSERT(s->inflight >= 2); /* the send, and the waiting cancel */
	close(b); /* the send completes with an error while the cancel still waits */
	run_for(l, 30);
	ASSERT_EQ(bst_test_uring_pending_cancels(l), 1);
	/* the old socket is still allocated: a new socket gets another slot */
	int p[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
	bst_test_uring_sqe_fail = 0;
	bst_sock *s2 = bst_sock_wrap(l, p[0]);
	ASSERT(s2 != s);
	bst_chain c2;
	bst_chain_init(&c2, slab);
	bst_buf *big2 = mem_buf(0, 16u << 20);
	ASSERT_EQ(bst_chain_add_mem(&c2, big2, 0, 16u << 20), 0);
	sendres r2 = {.l = l};
	ASSERT_EQ(bst_io_send(s2, &c2, on_done, &r2), 0);
	run_for(l, 40); /* the retry goes in now: it must hit nothing of s2 */
	ASSERT_EQ(bst_test_uring_pending_cancels(l), 0);
	ASSERT_EQ(r2.calls, 0);
	bst_sock_close(s2);
	bst_chain_clear(&c2);
	bst_buf_unref(big2);
	bst_chain_clear(&c);
	bst_buf_unref(big);
	close(p[1]);
	bst_slab_free(slab);
	bst_loop_free(l);
}

TEST(send_tag_seeded_per_socket)
{
	bst_loop *l = uloop((bst_loop_cfg){0});
	ASSERT(l != NULL);
	int p[2], q[2];
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, q), 0);
	bst_sock *s1 = bst_sock_wrap(l, p[0]), *s2 = bst_sock_wrap(l, q[0]);
	ASSERT(s1->u.s_tag != s2->u.s_tag);
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s1, &c, on_done, &r), 0);
	ASSERT(s1->u.s_tag != 1); /* not every first send uses tag 1 */
	run_until(l, &r.done, 1000);
	bst_sock_close(s1);
	bst_sock_close(s2);
	close(p[1]);
	close(q[1]);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* SQPOLL: the SQ thread does not take the cancel in time (simulated): the close warns and
 * keeps the fd open. */
TEST(sqpoll_stall_keeps_fd_and_warns)
{
	bst_loop *l = uloop((bst_loop_cfg){.uring_sqpoll = 20});
	ASSERT(l != NULL);
	int a, b;
	ASSERT_EQ(tcp_pair(&a, &b), 0);
	bst_sock *s = bst_sock_wrap(l, a);
	bst_slab *slab = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, slab);
	bst_buf *big = mem_buf(0, 16u << 20);
	ASSERT_EQ(bst_chain_add_mem(&c, big, 0, 16u << 20), 0);
	sendres r = {.l = l};
	ASSERT_EQ(bst_io_send(s, &c, on_done, &r), 0);
	run_for(l, 20);
	char logbuf[512];
	log_begin(BST_LOG_WARN);
	bst_test_uring_sqpoll_stall = 1;
	bst_sock_close(s);
	bst_test_uring_sqpoll_stall = 0;
	log_end(logbuf, sizeof logbuf);
	ASSERT(s->fd_held);
	ASSERT(strstr(logbuf, "SQ thread did not take") != NULL);
	/* the cancel was prepared: it completes and the socket goes */
	run_for(l, 50);
	bst_chain_clear(&c);
	bst_buf_unref(big);
	close(b);
	bst_slab_free(slab);
	bst_loop_free(l);
}

/* A failing wait while draining at loop free ends the drain early and says so. */
TEST(drain_wait_error_returns_early)
{
	fflush(stdout);
	pid_t pid = fork();
	ASSERT(pid >= 0);
	if (pid == 0) {
		bst_loop *l = uloop((bst_loop_cfg){0});
		int a, b;
		if (l == NULL || tcp_pair(&a, &b) != 0)
			_exit(2);
		bst_sock *s = bst_sock_wrap(l, a);
		bst_io_recv_start(s, on_rx_drop, NULL);
		run_for(l, 10);
		bst_sock_close(s);
		char buf[1024];
		log_begin(BST_LOG_ERROR);
		uint64_t t0 = mono_ms();
		bst_test_uring_drain_wait_err = 1;
		bst_loop_free(l);
		uint64_t spent = mono_ms() - t0;
		log_end(buf, sizeof buf);
		/* _exit: memory the kernel may still use is leaked on purpose */
		_exit(strstr(buf, "waiting for cancelled operations") != NULL &&
				      strstr(buf, "File exists") != NULL && spent < 500
			      ? 0
			      : 3);
	}
	int st = 0;
	ASSERT_EQ(waitpid(pid, &st, 0), pid);
	ASSERT(WIFEXITED(st));
	ASSERT_EQ(WEXITSTATUS(st), 0);
}

TAP_MAIN()

/* io_uring backend (architecture section 3): ring setup, dispatch, polls, wake, drain.
 * Stream I/O is uring_net.c, buffers and pipes uring_bufs.c.
 *
 * Setup: the ring starts IORING_SETUP_R_DISABLED with SINGLE_ISSUER, DEFER_TASKRUN,
 * COOP_TASKRUN and SUBMIT_ALL, stepping down through fewer flags when the kernel answers
 * EINVAL (bst_uring_setup_flags_ says where it ended). Everything is registered, then the
 * Task 8 hook runs (restrictions), then the ring is enabled. SINGLE_ISSUER binds the ring
 * to the thread that enables it: bst_loop_new, run and free belong to the loop's thread.
 *
 * Wake: an eventfd written by any thread and read by an IORING_OP_READ that the loop
 * re-arms after each completion. Only the loop thread submits (no IORING_OP_MSG_RING,
 * which would submit from the waking thread and break SINGLE_ISSUER).
 *
 * Dispatch: completions are copied out of the CQ ring into a batch of at most a CQ's
 * worth; what does not fit stays in the ring (a full ring makes the kernel end multishot
 * operations, which re-arm, rather than drop anything). Each dispatch handles at most
 * BST_RECV_BUDGET recv and BST_ACCEPT_BUDGET accept completions per socket, as epoll does
 * per wakeup; later ones of that socket are carried, in order, to the next dispatch and
 * the wait does not block meanwhile. IORING_SQ_CQ_OVERFLOW (completions parked in the
 * kernel's overflow list) is flushed with a GETEVENTS enter before waiting again.
 *
 * Lifetime: every SQE that names a socket holds one s->inflight until its last
 * completion (the one without IORING_CQE_F_MORE); a closed socket is freed only at zero.
 * The tag in user_data tells a stale completion (an earlier arm) from the live one. */
#include "io/uring_priv.h"

#include "core/log.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

int (*bst_uring_pre_enable_)(struct io_uring *ring);

/* Every opcode the backend may submit (a kernel without SENDMSG_ZC never sees it). */
const uint8_t bst_uring_opcodes_[] = {
	IORING_OP_NOP,	   IORING_OP_POLL_ADD, IORING_OP_ASYNC_CANCEL, IORING_OP_READ,
	IORING_OP_RECV,	   IORING_OP_SENDMSG,  IORING_OP_SENDMSG_ZC,   IORING_OP_ACCEPT,
	IORING_OP_CONNECT, IORING_OP_SPLICE,
};
const unsigned bst_uring_nopcodes_ = sizeof bst_uring_opcodes_;
const uint8_t bst_uring_register_ops_[] = {IORING_UNREGISTER_PBUF_RING,
					   IORING_UNREGISTER_RING_FDS};
const unsigned bst_uring_nregister_ = sizeof bst_uring_register_ops_;

/* Without these the backend cannot work (Task 4 then falls back to epoll). */
static const uint8_t required_ops[] = {
	IORING_OP_NOP,	  IORING_OP_POLL_ADD, IORING_OP_ASYNC_CANCEL, IORING_OP_READ, IORING_OP_RECV,
	IORING_OP_SENDMSG, IORING_OP_ACCEPT,  IORING_OP_CONNECT,      IORING_OP_SPLICE,
};

#ifdef BST_TEST
unsigned bst_test_uring_reject, bst_test_uring_cq, bst_test_uring_nofeat;
int bst_test_uring_drain_ms = -1;
unsigned bst_test_uring_sqe_fail, bst_test_uring_peer_fail, bst_test_uring_splice_einval;
unsigned bst_test_uring_pipes_max, bst_test_uring_sendfiles, bst_test_uring_copies;
unsigned bst_test_uring_overflows, bst_test_uring_rearms, bst_test_uring_nobufs;
unsigned bst_test_uring_accept_arms, bst_test_uring_splices, bst_test_uring_pipes_made;
unsigned bst_test_uring_zc, bst_test_uring_drained, bst_test_uring_splice_outs;
unsigned bst_test_uring_sqpoll_stall, bst_test_uring_drain_wait_err, bst_test_uring_copy_fail;

/* BST_TEST_URING_FAIL=<step>:<errno> injects a setup error (the number is the errno).
 * Steps: setup (every ring creation attempt), defer_taskrun, single_issuer, sqpoll (attempts
 * with that flag), probe (a required opcode is reported missing, failing with that errno),
 * napi (NAPI registration), enable (enabling the ring: a failure after setup and probe). Compiled only into BST_TEST builds: a release binary has no such
 * string. */
static int test_fail(const char *step)
{
	const char *e = getenv("BST_TEST_URING_FAIL");
	size_t n = strlen(step);
	if (e == NULL || strncmp(e, step, n) != 0 || e[n] != ':')
		return 0;
	return atoi(e + n + 1);
}
#endif

/* ---- user_data, SQEs ---- */

uint64_t bst_uring_ud_(unsigned kind, const void *p, uint16_t tag)
{
	uintptr_t a = (uintptr_t)p;
	/* Sockets come from a 16-byte aligned slab in a 48-bit user address space. */
	if ((a >> 48) != 0 || (a & 15u) != 0)
		abort();
	return (uint64_t)tag << 48 | a | kind;
}

static bst_sock *ud_sock(uint64_t ud)
{
	return (bst_sock *)(uintptr_t)(ud & 0x0000FFFFFFFFFFF0ull);
}

static uint64_t now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

/* SQPOLL: the kernel thread takes SQEs on its own schedule. Wait for it, by time. */
static bool sqpoll_wait(bst_uring *u, unsigned need_space)
{
#ifdef BST_TEST
	if (bst_test_uring_sqpoll_stall)
		return false; /* the SQ thread "does not take" anything */
#endif
	struct io_uring *r = &u->ring;
	uint64_t end = now_us() + BST_URING_SQPOLL_WAIT_US;
	for (;;) {
		bool done = need_space ? io_uring_sq_space_left(r) >= need_space
				       : io_uring_sq_ready(r) == 0;
		if (done)
			return true;
		if (now_us() >= end)
			return false;
		sched_yield();
	}
}

struct io_uring_sqe *bst_uring_sqe_(bst_uring *u, unsigned need)
{
	struct io_uring *r = &u->ring;
#ifdef BST_TEST
	if (bst_test_uring_sqe_fail > 0) {
		bst_test_uring_sqe_fail--;
		return NULL;
	}
#endif
	if (io_uring_sq_space_left(r) < need) {
		(void)io_uring_submit(r);
		if ((u->setup_flags & IORING_SETUP_SQPOLL) && !sqpoll_wait(u, need))
			return NULL;
		if (io_uring_sq_space_left(r) < need)
			return NULL;
	}
	return io_uring_get_sqe(r);
}

void bst_uring_prep_(bst_uring *u, struct io_uring_sqe *sqe, unsigned kind, bst_sock *s,
		     uint16_t tag)
{
	io_uring_sqe_set_data64(sqe, bst_uring_ud_(kind, s, tag));
	u->prepped++;
	u->live++;
	if (s != NULL) {
		s->inflight++;
		s->u.prep_seq = u->prepped;
	}
}

static void prep_cancel(bst_uring *u, struct io_uring_sqe *sqe, uint64_t ud)
{
	io_uring_prep_cancel64(sqe, ud, IORING_ASYNC_CANCEL_ALL);
	io_uring_sqe_set_data64(sqe, BST_UK_IGNORE);
	u->prepped++;
}

bool bst_uring_cancel_(bst_uring *u, uint64_t ud)
{
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	if (sqe != NULL) {
		prep_cancel(u, sqe, ud);
		return true;
	}
	/* No SQE now (the SQ is full and the kernel is not taking it): retried before every
	 * wait until it goes in. Its target cannot be re-armed under the same user_data: tags
	 * are retired by every cancel. */
	if (u->npcan == u->capcan) {
		unsigned cap = u->capcan ? u->capcan * 2 : 16;
		uint64_t *p = realloc(u->pcan, cap * sizeof *p);
		if (p == NULL) {
			bst_log(BST_LOG_ERROR, "io_uring: out of memory queueing a cancel; the "
					       "request completes on its own");
			return false;
		}
		u->pcan = p;
		u->capcan = cap;
	}
	u->pcan[u->npcan++] = ud;
	/* The target must not be freed, and its slab slot reused, while the cancel waits: the
	 * retry would cancel whatever new request carries the same (kind, socket, tag). */
	ud_sock(ud)->inflight++;
	return false;
}

static void retry_cancels(bst_uring *u)
{
	unsigned k = 0;
	for (unsigned i = 0; i < u->npcan; i++) {
		struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
		if (sqe == NULL) {
			u->pcan[k++] = u->pcan[i];
		} else {
			prep_cancel(u, sqe, u->pcan[i]);
			bst_sock_release_(ud_sock(u->pcan[i])); /* submitted by this wait */
		}
	}
	u->npcan = k;
}

bool bst_uring_flush_(bst_uring *u)
{
	int rc = io_uring_submit(&u->ring);
	if (u->setup_flags & IORING_SETUP_SQPOLL) {
		/* The SQ thread advances the head only after issuing what it took. */
		if (sqpoll_wait(u, 0))
			return true;
		bst_log(BST_LOG_WARN, "io_uring: the SQ thread did not take requests within %u us",
			BST_URING_SQPOLL_WAIT_US);
		return false;
	}
	return rc >= 0 && io_uring_sq_ready(&u->ring) == 0;
}

bool bst_uring_unsubmitted_(bst_uring *u, const bst_sock *s)
{
	return s->u.prep_seq > u->prepped - io_uring_sq_ready(&u->ring);
}

bool bst_uring_budget_(bst_uring *u, bst_sock *s, unsigned max)
{
	if (s->closed || u->draining)
		return true;
	if (s->u.epoch != u->epoch) {
		s->u.epoch = u->epoch;
		s->u.cnt = 0;
		s->u.deferred = false;
	}
	if (s->u.deferred || s->u.cnt >= max) {
		s->u.deferred = true;
		return false;
	}
	s->u.cnt++;
	return true;
}

/* ---- wake ---- */

static void arm_wake(bst_uring *u)
{
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	if (sqe == NULL)
		return; /* retried before the next wait */
	io_uring_prep_read(sqe, u->efd, &u->evbuf, sizeof u->evbuf, 0);
	bst_uring_prep_(u, sqe, BST_UK_WAKE, NULL, 0);
	u->wake_live = true;
}

/* The read is armed again before the next wait (ur_wait). */
static void wake_cqe(bst_uring *u, const bst_ucqe *e)
{
	u->wake_live = false;
	if (!u->draining && e->res > 0)
		bst_loop_woken_(u->loop);
}

static void ur_wake(bst_loop *l)
{
	bst_uring *u = l->be;
	int saved = errno;
	uint64_t one = 1;
	ssize_t r = write(u->efd, &one, sizeof one); /* touches no ring state */
	(void)r;
	errno = saved;
}

/* ---- completions ---- */

static void poll_cqe(bst_uring *u, bst_sock *s, const bst_ucqe *e)
{
	uint16_t tag = (uint16_t)(e->ud >> 48);
	if (s->closed || u->draining || !s->u.poll_live || tag != s->u.poll_tag)
		return; /* closed, or an earlier arm */
	s->u.poll_live = false;
	bst_sock_ready_(s, e->res < 0 ? POLLERR : (uint32_t)e->res);
}

static void handle(bst_uring *u, const bst_ucqe *e)
{
	unsigned kind = (unsigned)(e->ud & 15u);
	if (kind == BST_UK_IGNORE)
		return;
	bool last = !(e->flags & IORING_CQE_F_MORE);
	if (last)
		u->live--;
	if (kind == BST_UK_WAKE) {
		wake_cqe(u, e);
		return;
	}
	bst_sock *s = ud_sock(e->ud);
	if (last)
		bst_sock_release_(s); /* freed only at the end of the iteration */
	switch (kind) {
	case BST_UK_POLL:
		poll_cqe(u, s, e);
		break;
	case BST_UK_RECV:
		bst_uring_recv_cqe_(u, s, e, last);
		break;
	case BST_UK_ACCEPT:
		bst_uring_accept_cqe_(u, s, e, last);
		break;
	case BST_UK_TEST:
		break;
	default:
		bst_uring_send_cqe_(u, s, kind, e, last);
		break;
	}
}

static bool cq_overflowed(bst_uring *u)
{
	return (IO_URING_READ_ONCE(*u->ring.sq.kflags) & IORING_SQ_CQ_OVERFLOW) != 0;
}

/* Copy completions into the batch after the carried ones, flushing the kernel's overflow
 * list while there is room. */
static void reap(bst_uring *u)
{
	struct io_uring *r = &u->ring;
	for (;;) {
		struct io_uring_cqe *c;
		unsigned k = 0;
		while (u->n < u->cap && io_uring_peek_cqe(r, &c) == 0 && c != NULL) {
			bst_ucqe *e = &u->batch[u->n++];
			e->ud = c->user_data;
			e->res = c->res;
			e->flags = c->flags;
			e->copy = NULL;
			if (c->flags & IORING_CQE_F_BUFFER)
				u->taken++;
			io_uring_cqe_seen(r, c);
			k++;
		}
		if (u->n >= u->cap || !cq_overflowed(u))
			break;
		if (io_uring_get_events(r) < 0 || (k == 0 && io_uring_cq_ready(r) == 0))
			break;
	}
	unsigned ko = IO_URING_READ_ONCE(*r->cq.koverflow);
	if (ko != u->koverflow) {
		bst_log(BST_LOG_ERROR,
			"io_uring: the kernel dropped %u completion(s) (CQ overflow without memory)",
			ko - u->koverflow);
		u->koverflow = ko;
	}
}

static int ur_wait(bst_loop *l, int timeout_ms)
{
	bst_uring *u = l->be;
	struct io_uring *r = &u->ring;
	retry_cancels(u);
	if (!u->wake_live)
		arm_wake(u);
	bst_uring_net_prewait_(u);
	bool ovf = cq_overflowed(u); /* completions wait in the kernel's overflow list */
#ifdef BST_TEST
	if (ovf)
		bst_test_uring_overflows++;
#endif
	if (u->carry > 0 || u->pend != NULL || io_uring_cq_ready(r) > 0 || ovf)
		timeout_ms = 0;
	int rc;
	if (timeout_ms == 0) {
		rc = io_uring_submit_and_get_events(r);
	} else {
		struct __kernel_timespec ts = {.tv_sec = timeout_ms / 1000,
					       .tv_nsec = (long long)(timeout_ms % 1000) * 1000000};
		struct io_uring_cqe *cqe;
		rc = io_uring_submit_and_wait_timeout(r, &cqe, 1, timeout_ms < 0 ? NULL : &ts, NULL);
	}
	if (rc < 0 && rc != -ETIME && rc != -EINTR && rc != -EAGAIN && rc != -EBUSY)
		return rc;
	u->n = u->carry;
	reap(u);
	if (u->n > 0)
		return u->n > INT_MAX ? INT_MAX : (int)u->n;
	return u->pend != NULL ? 1 : 0;
}

static void ur_dispatch(bst_loop *l, int n)
{
	(void)n; /* the batch is ours */
	bst_uring *u = l->be;
	u->epoch++;
	bst_uring_net_pend_(u);
	unsigned keep = 0, total = u->n, carried = u->carry;
	for (unsigned i = 0; i < total; i++) {
		bst_ucqe e = u->batch[i];
		unsigned kind = (unsigned)(e.ud & 15u);
		bst_sock *s = ud_sock(e.ud);
		bool recv = kind == BST_UK_RECV, was = i < carried;
		if (recv && was)
			s->u.carried--;
		if ((recv && !bst_uring_budget_(u, s, BST_RECV_BUDGET)) ||
		    (kind == BST_UK_ACCEPT && !bst_uring_budget_(u, s, BST_ACCEPT_BUDGET))) {
			if (recv)
				bst_uring_net_carry_(u, s, &e);
			u->batch[keep++] = e;
			continue;
		}
		handle(u, &e);
		if (recv && was)
			bst_uring_net_uncarry_(u, s);
	}
	u->carry = u->n = keep;
}

/* ---- polls, sockets ---- */

static int ur_poll_arm(bst_sock *s, uint32_t events)
{
	bst_uring *u = s->loop->be;
	if (s->u.poll_live) { /* a replacement: the old arm completes as stale */
		bst_uring_cancel_(u, bst_uring_ud_(BST_UK_POLL, s, s->u.poll_tag));
		s->u.poll_live = false;
		if ((uint16_t)s->gen == s->u.poll_tag)
			s->gen++;
	}
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	if (sqe == NULL)
		return -EBUSY;
	io_uring_prep_poll_add(sqe, s->fd, events);
	uint16_t tag = (uint16_t)s->gen;
	bst_uring_prep_(u, sqe, BST_UK_POLL, s, tag);
	s->u.poll_live = true;
	s->u.poll_tag = tag;
	s->registered = true;
	return 0;
}

static void ur_sock_detach(bst_sock *s)
{
	bst_uring *u = s->loop->be;
	bool ok = true;
	if (s->u.poll_live) {
		ok = bst_uring_cancel_(u, bst_uring_ud_(BST_UK_POLL, s, s->u.poll_tag));
		s->u.poll_live = false;
	}
	bool sending = s->u.s_out > 0;
	ok &= bst_uring_net_detach_(u, s);
	/* SQEs not picked up yet name s->fd by number: issue them while it still is this
	 * socket. A send is cancelled now, so the caller may free its chain on return. */
	if (sending || bst_uring_unsubmitted_(u, s))
		ok &= bst_uring_flush_(u);
	/* Keep the number while a request may still resolve it: a splice opens its files only
	 * when it runs, and a request not taken or not cancelled yet names it too. */
	if ((s->u.late > 0 || !ok) && !s->borrowed)
		s->fd_held = true;
	s->registered = false;
}

/* ---- setup and teardown ---- */

static int setup_ring_try(bst_uring *u, const bst_loop_cfg *cfg, unsigned sqpoll, bst_err *err)
{
	unsigned entries = cfg != NULL && cfg->uring_entries ? cfg->uring_entries
							       : BST_URING_ENTRIES_DEFAULT;
	if (entries > BST_URING_ENTRIES_MAX)
		entries = BST_URING_ENTRIES_MAX;
	const unsigned base = IORING_SETUP_R_DISABLED | IORING_SETUP_SUBMIT_ALL;
	/* SQPOLL refuses the task-run flags; SINGLE_ISSUER then names the SQ thread. */
	static const unsigned ladder[] = {
		IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN,
		IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN,
		IORING_SETUP_COOP_TASKRUN,
		0,
	};
	static const unsigned ladder_sqpoll[] = {
		IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER,
		IORING_SETUP_SQPOLL,
	};
	const unsigned *rungs = sqpoll ? ladder_sqpoll : ladder;
	unsigned nr = sqpoll ? 2 : 4;
	int rc = -EINVAL;
	for (unsigned i = 0; i < nr; i++) {
		struct io_uring_params p;
		memset(&p, 0, sizeof p);
		p.flags = base | rungs[i];
		p.sq_thread_idle = sqpoll;
#ifdef BST_TEST
		if (bst_test_uring_cq != 0) {
			p.flags |= IORING_SETUP_CQSIZE;
			p.cq_entries = bst_test_uring_cq;
		}
		/* a flag the kernel "rejects": the same EINVAL path as a real refusal */
		int inj = test_fail("setup");
			if (inj == 0 && (p.flags & IORING_SETUP_DEFER_TASKRUN))
				inj = test_fail("defer_taskrun");
			if (inj == 0 && (p.flags & IORING_SETUP_SINGLE_ISSUER))
				inj = test_fail("single_issuer");
			if (inj == 0 && (p.flags & IORING_SETUP_SQPOLL))
				inj = test_fail("sqpoll");
			if (inj != 0)
				rc = -inj;
			else if (p.flags & bst_test_uring_reject)
				rc = -EINVAL;
			else
				rc = io_uring_queue_init_params(entries, &u->ring, &p);
#else
		rc = io_uring_queue_init_params(entries, &u->ring, &p);
#endif
		if (rc == 0) {
			u->setup_flags = p.flags;
			u->kfeat = p.features;
			u->cap = p.cq_entries;
			return 0;
		}
		if (rc != -EINVAL)
			break;
	}
	u->ring.ring_fd = -1; /* a failed init may have zeroed it: never exit fd 0 */
	bst_err_set(err, "io_uring_setup: %s", strerror(-rc));
	return rc;
}

/* SQPOLL that the kernel refuses (EINVAL on both rungs, or EPERM: old kernels want
 * privileges for it) steps down to the plain ladder with a warning. */
static int setup_ring(bst_uring *u, const bst_loop_cfg *cfg, bst_err *err)
{
	unsigned sqpoll = cfg != NULL ? cfg->uring_sqpoll : 0;
	int rc = setup_ring_try(u, cfg, sqpoll, err);
	if (rc != 0 && sqpoll != 0 && (rc == -EINVAL || rc == -EPERM)) {
		int first = rc;
		rc = setup_ring_try(u, cfg, 0, err);
		/* Say SQPOLL was the problem only when taking it away fixed it: if the plain ring
		 * fails too, the setup error (and the caller's fallback line) is the real reason. */
		if (rc == 0)
			bst_log(BST_LOG_WARN, "io_uring SQPOLL is refused here (%s): uring_sqpoll ignored",
				strerror(-first));
	}
	return rc;
}

static int probe(bst_uring *u, bst_err *err)
{
	static const struct {
		unsigned bit;
		const char *name;
	} need[] = {
		{IORING_FEAT_NODROP, "IORING_FEAT_NODROP"},
		{IORING_FEAT_EXT_ARG, "IORING_FEAT_EXT_ARG"},
		{IORING_FEAT_FAST_POLL, "IORING_FEAT_FAST_POLL"},
	};
	for (unsigned i = 0; i < sizeof need / sizeof need[0]; i++)
		if (!(u->kfeat & need[i].bit)) {
			bst_err_set(err, "io_uring: the kernel lacks %s", need[i].name);
			return -EOPNOTSUPP;
		}
#ifdef BST_TEST
	if (test_fail("probe") != 0) {
		bst_err_set(err, "io_uring: the kernel lacks opcode %u", required_ops[0]);
		return -test_fail("probe");
	}
#endif
	struct io_uring_probe *pr = io_uring_get_probe_ring(&u->ring);
	if (pr == NULL) {
		bst_err_set(err, "io_uring: opcode probe failed");
		return -EOPNOTSUPP;
	}
	int rc = 0;
	for (unsigned i = 0; i < sizeof required_ops && rc == 0; i++)
		if (!io_uring_opcode_supported(pr, required_ops[i])) {
			bst_err_set(err, "io_uring: the kernel lacks opcode %u", required_ops[i]);
			rc = -EOPNOTSUPP;
		}
	/* Buffer rings are required (5.19), and multishot accept came with them. Multishot
	 * recv came in 6.0 with IORING_OP_SEND_ZC, which stands in for it in the probe. */
	u->feat = BST_URF_ACCEPT_MSHOT;
	if (io_uring_opcode_supported(pr, IORING_OP_SEND_ZC))
		u->feat |= BST_URF_RECV_MSHOT;
	if (io_uring_opcode_supported(pr, IORING_OP_SENDMSG_ZC))
		u->feat |= BST_URF_SENDMSG_ZC;
	io_uring_free_probe(pr);
#ifdef BST_TEST
	u->feat &= ~bst_test_uring_nofeat;
#endif
	return rc;
}

static void ur_free(bst_uring *u)
{
	if (u->br != NULL || u->bhdr != NULL || u->bmem != NULL)
		bst_ubufs_free_(u);
	if (u->ring.ring_fd >= 0)
		io_uring_queue_exit(&u->ring);
	if (u->efd >= 0)
		close(u->efd);
	bst_upipes_free_(u);
	if (!u->leak)
		bst_slab_free(u->sends);
	free(u->pcan);
	free(u->batch);
	free(u);
}

/* Negative errno on failure (the caller classifies it: ENOSYS, EPERM, EOPNOTSUPP fall back
 * under backend auto), with err filled in. */
static int ur_open(bst_loop *l, const bst_loop_cfg *cfg, bst_err *err, bst_open_stage *stage)
{
	*stage = BST_OPEN_OTHER;
	bst_uring *u = calloc(1, sizeof *u);
	if (u == NULL) {
		bst_err_set(err, "out of memory");
		return -ENOMEM;
	}
	u->loop = l;
	u->efd = -1;
	u->ring.ring_fd = -1;
	int ret = setup_ring(u, cfg, err);
	if (ret != 0) {
		*stage = BST_OPEN_SETUP;
		ur_free(u);
		return ret;
	}
	ret = probe(u, err);
	if (ret != 0) {
		*stage = BST_OPEN_PROBE;
		goto fail;
	}
	ret = -ENOMEM;
	u->batch = calloc(u->cap, sizeof *u->batch);
	u->sends = bst_slab_new(sizeof(bst_usend), 16);
	u->efd = eventfd(0, EFD_CLOEXEC); /* blocking: the READ waits through io_uring's poll */
	if (u->batch == NULL || u->sends == NULL || u->efd < 0) {
		if (u->efd < 0)
			ret = -errno;
		bst_err_set(err, "io_uring: %s", u->efd < 0 ? strerror(errno) : "out of memory");
		goto fail;
	}
	ret = bst_ubufs_init_(u, cfg != NULL ? cfg->uring_bufs : 0, err);
	if (ret != 0)
		goto fail;
	if (io_uring_register_ring_fd(&u->ring) == 1)
		u->feat |= BST_URF_RING_FD;
	u->napi_asked = cfg != NULL && cfg->uring_napi != 0;
	if (u->napi_asked) {
		struct io_uring_napi napi = {.busy_poll_to = cfg->uring_napi, .prefer_busy_poll = 1};
		int nrc = io_uring_register_napi(&u->ring, &napi);
#ifdef BST_TEST
		if (test_fail("napi") != 0)
			nrc = -test_fail("napi");
#endif
		if (nrc == 0) {
			u->feat |= BST_URF_NAPI;
		} else if (cfg->uring_napi_require) {
			bst_err_set(err, "io_uring: uring_napi is required but NAPI busy poll is not "
					 "available here (%s; it needs Linux 6.9)", strerror(-nrc));
			ret = -EOPNOTSUPP;
			goto fail;
		} else {
			bst_log(BST_LOG_WARN,
				"io_uring NAPI busy poll is not available here (%s): uring_napi ignored",
				strerror(-nrc));
		}
	}
	u->zc_min = cfg != NULL ? cfg->uring_send_zc_min : 0;
	if (bst_uring_pre_enable_ != NULL) {
		int rc = bst_uring_pre_enable_(&u->ring);
		if (rc != 0) {
			bst_err_set(err, "io_uring: restricting the ring failed: %s",
				    strerror(rc < 0 ? -rc : rc));
			ret = rc < 0 ? rc : -rc;
			goto fail;
		}
	}
	int rc = io_uring_enable_rings(&u->ring);
#ifdef BST_TEST
	if (test_fail("enable") != 0)
		rc = -test_fail("enable");
#endif
	if (rc != 0) {
		bst_err_set(err, "io_uring: enabling the ring: %s", strerror(-rc));
		ret = rc;
		goto fail;
	}
	l->be = u;
	arm_wake(u);
	return 0;
fail:
	ur_free(u);
	return ret < 0 ? ret : -EIO;
}

static void ur_drain(bst_loop *l)
{
	bst_uring *u = l->be;
	u->draining = true;
	bst_uring_net_drain_(u);
	for (unsigned i = 0; i < u->npcan; i++) /* ASYNC_CANCEL_ANY below covers them */
		bst_sock_release_(ud_sock(u->pcan[i]));
	u->npcan = 0;
	unsigned bound = BST_URING_DRAIN_MS;
#ifdef BST_TEST
	if (bst_test_uring_drain_ms >= 0)
		bound = (unsigned)bst_test_uring_drain_ms;
	bst_test_uring_drained = 0;
#endif
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	if (sqe != NULL) {
		io_uring_prep_cancel64(sqe, 0, IORING_ASYNC_CANCEL_ANY);
		io_uring_sqe_set_data64(sqe, BST_UK_IGNORE);
		u->prepped++;
	}
	uint64_t t0 = bst_mono_ms_();
	for (;;) {
		for (unsigned i = 0; i < u->n; i++) {
			handle(u, &u->batch[i]); /* no callbacks while draining */
#ifdef BST_TEST
			bst_test_uring_drained++;
#endif
		}
		u->n = u->carry = 0;
		uint64_t spent = bst_mono_ms_() - t0;
		if (u->live == 0 || spent >= bound)
			break;
		uint64_t left = bound - spent;
		struct __kernel_timespec ts = {.tv_sec = (long long)(left / 1000),
					       .tv_nsec = (long long)(left % 1000) * 1000000};
		struct io_uring_cqe *cqe;
		int rc;
#ifdef BST_TEST
		if (bst_test_uring_drain_wait_err) { /* the wait "fails" once, nothing is reaped */
			bst_test_uring_drain_wait_err = 0;
			rc = -EEXIST;
		} else
#endif
		{
			rc = io_uring_submit_and_wait_timeout(&u->ring, &cqe, 1, &ts, NULL);
			reap(u);
		}
		if (rc < 0 && rc != -ETIME && rc != -EINTR && u->n == 0) {
			bst_log(BST_LOG_ERROR, "io_uring: waiting for cancelled operations at loop "
					       "free failed: %s", strerror(-rc));
			break;
		}
	}
	if (u->live > 0) {
		bst_log(BST_LOG_ERROR,
			"io_uring: %u operation(s) still in flight %u ms after cancelling them at "
			"loop free; the memory they may use is leaked",
			u->live, bound);
		u->leak = true;
	}
}

static void ur_close(bst_loop *l)
{
	bst_uring *u = l->be;
	if (u->bout != 0) {
		bst_log(BST_LOG_ERROR, "bst_loop_free with %zu recv buffer(s) still held", u->bout);
#ifdef BST_TEST
		abort();
#endif
	}
	ur_free(u);
	l->be = NULL;
}

/* ---- private interface ---- */

static const bst_uring *uring_of(const bst_loop *l)
{
	return l->ops->id == BST_BACKEND_URING ? l->be : NULL;
}

unsigned bst_uring_setup_flags_(const bst_loop *l)
{
	const bst_uring *u = uring_of(l);
	return u != NULL ? u->setup_flags : 0;
}

void bst_uring_describe_(const bst_loop *l, char *buf, size_t cap)
{
	static const struct {
		unsigned bit;
		const char *name;
	} fl[] = {{IORING_SETUP_SQPOLL, "SQPOLL"},
		  {IORING_SETUP_SINGLE_ISSUER, "SINGLE_ISSUER"},
		  {IORING_SETUP_DEFER_TASKRUN, "DEFER_TASKRUN"},
		  {IORING_SETUP_COOP_TASKRUN, "COOP_TASKRUN"}};
	unsigned have = bst_uring_setup_flags_(l);
	unsigned want = (have & IORING_SETUP_SQPOLL)
				? IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER
				: IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN |
					  IORING_SETUP_COOP_TASKRUN;
	size_t n = (size_t)snprintf(buf, cap, "flags");
	const char *sep = " ";
	for (unsigned i = 0; i < 4 && n < cap; i++)
		if (have & fl[i].bit) {
			n += (size_t)snprintf(buf + n, cap - n, "%s%s", sep, fl[i].name);
			sep = ",";
		}
	if (sep[0] == ' ' && n < cap)
		n += (size_t)snprintf(buf + n, cap - n, " none");
	for (unsigned i = 0; i < 4 && n < cap; i++)
		if ((want & fl[i].bit) && !(have & fl[i].bit))
			n += (size_t)snprintf(buf + n, cap - n, "; %s refused", fl[i].name);
	const bst_uring *u = uring_of(l);
	if (u != NULL && n < cap)
		(void)snprintf(buf + n, cap - n, "; NAPI %s",
			       (u->feat & BST_URF_NAPI) ? "on" : u->napi_asked ? "unavailable" : "off");
}

unsigned bst_uring_features_(const bst_loop *l)
{
	const bst_uring *u = uring_of(l);
	return u != NULL ? u->feat : 0;
}

#ifdef BST_TEST
struct io_uring *bst_test_uring_ring(bst_loop *l)
{
	return &((bst_uring *)l->be)->ring;
}

unsigned bst_test_uring_dropped(bst_loop *l)
{
	bst_uring *u = l->be;
	return IO_URING_READ_ONCE(*u->ring.cq.koverflow);
}

unsigned bst_test_uring_live(bst_loop *l)
{
	return ((bst_uring *)l->be)->live;
}

unsigned bst_test_uring_pending_cancels(bst_loop *l)
{
	return ((bst_uring *)l->be)->npcan;
}
#endif

const bst_loop_ops bst_loop_uring_ops = {
	.id = BST_BACKEND_URING,
	.open = ur_open,
	.close = ur_close,
	.wait = ur_wait,
	.dispatch = ur_dispatch,
	.poll_arm = ur_poll_arm,
	.sock_detach = ur_sock_detach,
	.wake = ur_wake,
	.drain = ur_drain,
	.net = &bst_uring_net_ops_,
};

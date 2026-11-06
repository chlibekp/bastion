/* io_uring stream input behind net.h's API (net_common.c checks arguments and sets
 * fields, then calls these through ops->net); the send side is uring_send.c.
 *
 * Accept: multishot IORING_OP_ACCEPT (single-shot re-armed where missing). The peer comes
 * from getpeername: a multishot accept has one address buffer for all its connections.
 * A connection completed for a stopped or closed listener, or whose peer cannot be read
 * (reset first), is closed, never leaked.
 *
 * Recv: multishot IORING_OP_RECV over the loop's provided-buffer ring (single-shot where
 * missing). The kernel ends a multishot recv by itself (CQ full, no buffer): it is armed
 * again, at once or, after -ENOBUFS, once a buffer comes back. Copy-out (uring_bufs.c)
 * keeps held buffers from emptying the ring, and a socket over its per-dispatch budget is
 * parked (its recv cancelled) until its carried completions are delivered. Stop cancels
 * the recv, but data the kernel already took from the socket still completes: it goes to
 * a per-socket stash of copies (with any end of stream), delivered first after the next
 * start, so a stop loses and reorders nothing. */
#include "io/uring_priv.h"

#include "core/log.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- lists: each membership holds an inflight, so a closed socket outlives it ---- */

static void list_wait(bst_uring *u, bst_sock *s)
{
	s->u.r_wait = true;
	if (s->u.r_wlisted)
		return;
	s->u.r_wlisted = true;
	s->u.wnext = u->bwait;
	u->bwait = s;
	s->inflight++;
}

static void list_pend(bst_uring *u, bst_sock *s)
{
	if (s->u.r_pend)
		return;
	s->u.r_pend = true;
	s->u.pnext = u->pend;
	u->pend = s;
	s->inflight++;
}

void bst_uring_net_drain_(bst_uring *u)
{
	while (u->bwait != NULL) {
		bst_sock *s = u->bwait;
		u->bwait = s->u.wnext;
		s->u.r_wlisted = s->u.r_wait = false;
		bst_sock_release_(s);
	}
	while (u->pend != NULL) {
		bst_sock *s = u->pend;
		u->pend = s->u.pnext;
		s->u.r_pend = false;
		bst_sock_release_(s);
	}
}

/* ---- recv ---- */

static int arm_recv(bst_uring *u, bst_sock *s)
{
	if (s->u.r_live)
		return 0;
	if (bst_ubufs_avail_(u) == 0) {
		list_wait(u, s);
		return 0;
	}
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	if (sqe == NULL)
		return -EBUSY;
	bool m = (u->feat & BST_URF_RECV_MSHOT) != 0;
	if (m)
		io_uring_prep_recv_multishot(sqe, s->fd, NULL, 0, 0);
	else
		io_uring_prep_recv(sqe, s->fd, NULL, BST_RECV_BUF_SIZE, 0);
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = BST_URING_BGID;
	uint16_t tag = (uint16_t)s->recv_epoch;
	bst_uring_prep_(u, sqe, BST_UK_RECV, s, tag);
	s->u.r_live = true;
	s->u.r_mshot = m;
	s->u.r_acc = false;
	s->u.r_tag = tag;
	return 0;
}

static void stash_push(bst_sock *s, bst_rbuf *r)
{
	r->next = NULL;
	if (s->u.st_tail != NULL)
		s->u.st_tail->next = r;
	else
		s->u.st_head = r;
	s->u.st_tail = r;
}

static bst_rbuf *stash_pop(bst_sock *s)
{
	bst_rbuf *r = s->u.st_head;
	if (r != NULL) {
		s->u.st_head = r->next;
		if (s->u.st_head == NULL)
			s->u.st_tail = NULL;
	}
	return r;
}

static bool stash_empty(const bst_sock *s)
{
	return s->u.st_head == NULL && s->u.st_end == 0;
}

/* Data may go straight to the callback: nothing older is waiting to be delivered. */
static bool may_deliver(const bst_sock *s)
{
	return s->recv_on && stash_empty(s) && !s->u.r_pend;
}

/* Cancel the recv or accept in flight. Its tag (recv_epoch) is retired, so a re-arm can
 * never be hit by this cancel, even one that waits on the retry list. */
static bool cancel_r(bst_uring *u, bst_sock *s)
{
	bool ok = true;
	if (s->u.r_live) {
		ok = bst_uring_cancel_(u, bst_uring_ud_(s->u.r_acc ? BST_UK_ACCEPT : BST_UK_RECV, s,
							s->u.r_tag));
		s->u.r_live = false;
		s->recv_epoch++;
	}
	s->u.r_wait = false;
	s->u.r_parked = false;
	return ok;
}

/* EOF (0) or an error: the stream ends until the next start. */
static void recv_end(bst_uring *u, bst_sock *s, int err)
{
	s->recv_on = false;
	(void)cancel_r(u, s);
	s->recv_cb(s->recv_ud, NULL, err);
}

static void rearm_recv(bst_uring *u, bst_sock *s)
{
	if (arm_recv(u, s) != 0)
		recv_end(u, s, -EIO);
}

/* The data for the callback: the ring slot itself, or a copy when holding the slot could
 * stall other sockets (a small payload, or the ring under pressure). */
static bst_buf *for_caller(bst_uring *u, bst_ubuf *b)
{
	if (b->b.len < BST_URING_COPY_MAX || bst_ubufs_pressed_(u)) {
		bst_buf *c = bst_ubufs_copy_(u, b);
		if (c != NULL)
			return c;
	}
	return bst_ubufs_hand_(u, b);
}

void bst_uring_recv_cqe_(bst_uring *u, bst_sock *s, const bst_ucqe *e, bool last)
{
	bst_ubuf *b = NULL;
	if (e->flags & IORING_CQE_F_BUFFER)
		b = bst_ubufs_take_(u, e->flags >> IORING_CQE_BUFFER_SHIFT,
				    e->res > 0 ? (size_t)e->res : 0);
	bool cur = s->u.r_live && (uint16_t)(e->ud >> 48) == s->u.r_tag;
	if (cur && last)
		s->u.r_live = false;
	if (s->closed || u->draining) {
		bst_ubufs_recycle_(u, b);
		bst_buf_unref(e->copy);
		return;
	}
	int res = e->res;
	if (res > 0 && (b != NULL || e->copy != NULL)) {
		if (may_deliver(s)) {
			s->recv_cb(s->recv_ud, e->copy != NULL ? e->copy : for_caller(u, b), 0);
		} else {
			/* Stopped, or older data still to deliver. A stash may be held as long as
			 * the stream stays stopped: always a copy, never a ring slot. */
			bst_buf *c = e->copy != NULL ? e->copy : bst_ubufs_copy_(u, b);
			if (c != NULL) {
				stash_push(s, (bst_rbuf *)c);
			} else {
				bst_ubufs_recycle_(u, b);
				if (s->u.st_end == 0)
					s->u.st_end = -ENOMEM; /* the stream cannot go on without a gap */
			}
			if (s->recv_on)
				list_pend(u, s);
		}
	} else {
		bst_ubufs_recycle_(u, b);
		if (res == -ENOBUFS) {
#ifdef BST_TEST
			bst_test_uring_nobufs++;
#endif
			if (cur && last && s->recv_on) {
				if (bst_ubufs_avail_(u) > 0)
					rearm_recv(u, s);
				else
					list_wait(u, s);
			}
			return;
		}
		if (res == -ECANCELED)
			return; /* our cancel: stop, close or the budget */
		if (res == -EINVAL && s->u.r_mshot && cur) {
			u->feat &= ~BST_URF_RECV_MSHOT;
			bst_log(BST_LOG_WARN, "io_uring: multishot recv refused; using single-shot");
			if (s->recv_on)
				rearm_recv(u, s);
			return;
		}
		if (res == -EINTR || res == -EAGAIN) {
			if (cur && last && s->recv_on)
				rearm_recv(u, s);
			return;
		}
		if (res < 0 && res != -EPIPE)
			s->last_err = -res; /* a later EPIPE on send reports this */
		if (may_deliver(s)) {
			recv_end(u, s, res);
		} else {
			s->u.st_end = res == 0 ? 1 : res;
			if (s->recv_on)
				list_pend(u, s);
		}
		return;
	}
	if (!s->closed && cur && last && s->recv_on && !s->u.r_live && may_deliver(s)) {
#ifdef BST_TEST
		if (s->u.r_mshot)
			bst_test_uring_rearms++;
#endif
		rearm_recv(u, s); /* the kernel ended it (CQ full) or it was single-shot */
	}
}

void bst_uring_net_carry_(bst_uring *u, bst_sock *s, bst_ucqe *e)
{
	s->u.carried++;
	if ((e->flags & IORING_CQE_F_BUFFER) && e->res > 0 && bst_ubufs_pressed_(u)) {
		bst_ubuf *b = bst_ubufs_take_(u, e->flags >> IORING_CQE_BUFFER_SHIFT, (size_t)e->res);
		bst_buf *c = b != NULL ? bst_ubufs_copy_(u, b) : NULL;
		if (c != NULL) {
			e->copy = c;
			e->flags &= ~(uint32_t)IORING_CQE_F_BUFFER;
		}
	}
	/* Over budget: stop taking slots for s until its carry is delivered. */
	if (s->u.r_live && s->u.r_mshot && !s->u.r_acc && !s->closed) {
		(void)cancel_r(u, s);
		s->u.r_parked = true;
	}
}

void bst_uring_net_uncarry_(bst_uring *u, bst_sock *s)
{
	if (s->u.carried > 0 || !s->u.r_parked)
		return;
	s->u.r_parked = false;
	if (!s->closed && s->recv_on && !s->u.r_live && may_deliver(s))
		rearm_recv(u, s);
}

static void deliver_stash(bst_uring *u, bst_sock *s)
{
	while (!s->closed && s->recv_on && !stash_empty(s)) {
		if (!bst_uring_budget_(u, s, BST_RECV_BUDGET)) {
			list_pend(u, s);
			return;
		}
		bst_rbuf *r = stash_pop(s);
		if (r != NULL) {
			s->recv_cb(s->recv_ud, &r->b, 0);
			continue;
		}
		int end = s->u.st_end;
		s->u.st_end = 0;
		recv_end(u, s, end == 1 ? 0 : end);
		return;
	}
	if (!s->closed && s->recv_on && !s->u.r_live && !s->u.r_pend && !s->u.r_parked &&
	    stash_empty(s))
		rearm_recv(u, s);
}

void bst_uring_net_pend_(bst_uring *u)
{
	bst_sock *list = u->pend;
	u->pend = NULL;
	while (list != NULL) {
		bst_sock *s = list;
		list = s->u.pnext;
		s->u.r_pend = false;
		bst_sock_release_(s);
		if (!s->closed)
			deliver_stash(u, s);
	}
}

void bst_uring_net_prewait_(bst_uring *u)
{
	if (u->bwait == NULL || !u->breturned || bst_ubufs_avail_(u) == 0)
		return;
	u->breturned = false;
	bst_sock *list = u->bwait;
	u->bwait = NULL;
	while (list != NULL) {
		bst_sock *s = list;
		list = s->u.wnext;
		bool want = s->u.r_wait;
		s->u.r_wlisted = s->u.r_wait = false;
		bst_sock_release_(s);
		if (want && !s->closed && s->recv_on && may_deliver(s) && arm_recv(u, s) != 0)
			list_wait(u, s); /* no SQE now: next time */
	}
}

static int ur_recv_start(bst_sock *s)
{
	bst_uring *u = s->loop->be;
	if (!stash_empty(s)) {
		list_pend(u, s); /* delivered from the next dispatch, never from here */
		return 0;
	}
	return arm_recv(u, s);
}

static void ur_recv_stop(bst_sock *s)
{
	(void)cancel_r(s->loop->be, s);
}

/* ---- accept ---- */

static int arm_accept(bst_uring *u, bst_sock *s)
{
	if (s->u.r_live)
		return 0;
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	if (sqe == NULL)
		return -EBUSY;
	bool m = (u->feat & BST_URF_ACCEPT_MSHOT) != 0;
	if (m)
		io_uring_prep_multishot_accept(sqe, s->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	else
		io_uring_prep_accept(sqe, s->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	uint16_t tag = (uint16_t)s->recv_epoch;
	bst_uring_prep_(u, sqe, BST_UK_ACCEPT, s, tag);
	s->u.r_live = true;
	s->u.r_mshot = m;
	s->u.r_acc = true;
	s->u.r_tag = tag;
#ifdef BST_TEST
	bst_test_uring_accept_arms++;
#endif
	return 0;
}

static void accept_pause(bst_sock *s, int err)
{
	s->acc_on = false;
	s->acc_paused = true;
	s->acc_cb(s->acc_ud, -1, NULL, err);
}

static void accept_cqe(bst_uring *u, bst_sock *s, const bst_ucqe *e, bool last)
{
	bool cur = s->u.r_live && (uint16_t)(e->ud >> 48) == s->u.r_tag;
	if (cur && last)
		s->u.r_live = false;
	int res = e->res;
	if (res >= 0) {
		if (s->closed || u->draining || !s->acc_on) {
			close(res);
			return;
		}
		struct sockaddr_storage ss;
		socklen_t sl = sizeof ss;
		bst_sockaddr peer;
		bool named = getpeername(res, (struct sockaddr *)&ss, &sl) == 0;
#ifdef BST_TEST
		if (bst_test_uring_peer_fail > 0) {
			bst_test_uring_peer_fail--;
			named = false;
		}
#endif
		if (named) {
			bool ip = bst_net_peer_(&ss, &peer);
			s->acc_cb(s->acc_ud, res, ip ? &peer : NULL, 0);
		} else {
			close(res); /* reset before it was looked at: as ECONNABORTED, keep accepting */
		}
	} else if (s->closed || u->draining || res == -ECANCELED) {
		return;
	} else if (res == -EINTR || res == -EAGAIN || res == -ECONNABORTED || res == -EPROTO) {
		/* a connection that went away before it was accepted: keep accepting */
	} else if (res == -EINVAL && s->u.r_mshot && cur) {
		u->feat &= ~BST_URF_ACCEPT_MSHOT;
		bst_log(BST_LOG_WARN, "io_uring: multishot accept refused; using single-shot");
	} else {
		if (cur && s->acc_on) /* EMFILE, ENFILE, ENOMEM...: report and pause, never spin */
			accept_pause(s, res);
		return;
	}
	if (cur && last && !s->closed && s->acc_on && !s->u.r_live) {
#ifdef BST_TEST
		if (s->u.r_mshot)
			bst_test_uring_rearms++;
#endif
		if (arm_accept(u, s) != 0)
			accept_pause(s, -EIO);
	}
}

void bst_uring_accept_cqe_(bst_uring *u, bst_sock *s, const bst_ucqe *e, bool last)
{
	/* The last completion of the cancelled arm: CQEs arrive in order, so all it accepted went
	 * through the callback before this. The arm's tag is retired, so nothing re-arms. */
	bool end = s->u.acc_quiesce && last;
	accept_cqe(u, s, e, last);
	if (end && s->u.acc_quiesce && !s->closed) {
		s->u.acc_quiesce = false;
		s->acc_on = false;
		s->acc_cb(s->acc_ud, -1, NULL, -ECANCELED);
	}
}

static int ur_accept_start(bst_sock *ls)
{
	return arm_accept(ls->loop->be, ls);
}

static bool ur_accept_quiesce(bst_sock *ls)
{
	if (!ls->u.r_live) /* paused or ended: no completion is coming */
		return false;
	if (!cancel_r(ls->loop->be, ls))
		return false; /* no room for the cancel: the caller's plain stop retires the arm */
	ls->u.acc_quiesce = true;
	return true;
}

/* ---- close ---- */

bool bst_uring_net_detach_(bst_uring *u, bst_sock *s)
{
	bool ok = true;
	if (s->udp != NULL)
		ok = bst_uring_udp_detach_(u, s); /* retires r_live: cancel_r finds nothing */
	ok &= cancel_r(u, s);
	bst_rbuf *r;
	while ((r = stash_pop(s)) != NULL)
		bst_buf_unref(&r->b);
	s->u.st_end = 0;
	return bst_uring_send_detach_(u, s) && ok;
}

const bst_net_ops bst_uring_net_ops_ = {
	.accept_start = ur_accept_start,
	.accept_quiesce = ur_accept_quiesce,
	.recv_start = ur_recv_start,
	.recv_stop = ur_recv_stop,
	.send_start = bst_uring_send_start_,
	.connect = bst_uring_connect_,
	.send_kick = bst_uring_send_kick_,
};

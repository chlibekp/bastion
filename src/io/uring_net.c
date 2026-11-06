/* io_uring stream I/O behind net.h's API (net_common.c checks arguments and sets fields,
 * then calls these through ops->net).
 *
 * Accept: multishot IORING_OP_ACCEPT (single-shot re-armed where missing). The peer comes
 * from getpeername: a multishot accept has one address buffer for all its connections.
 * A connection completed for a stopped or closed listener is closed, never leaked.
 *
 * Recv: multishot IORING_OP_RECV over the loop's provided-buffer ring (single-shot where
 * missing). The kernel ends a multishot recv by itself (CQ full, no buffer): it is armed
 * again, at once or, after -ENOBUFS, once a buffer comes back. Stop cancels the recv, but
 * data the kernel already took from the socket still completes: it goes to a per-socket
 * stash (and so does an end of stream), delivered first after the next start, so a stop
 * loses and reorders nothing.
 *
 * Send: one round at a time, at most the send budget per round (one round per dispatch):
 * memory segments with SENDMSG (SENDMSG_ZC from uring_send_zc_min bytes; the chain is
 * consumed only when the kernel's notification says the pages are free), file segments
 * with SPLICE file -> pipe linked to SPLICE pipe -> socket, after the same residency probe
 * and pool readahead as epoll, so a cold file never stalls the loop or an io-wq worker.
 * A full socket makes the splice return -EAGAIN; the next round links POLL_ADD(POLLOUT)
 * before it. Splices name their fds only when they run, so they use a dup of the file fd
 * and keep the socket fd open (fd_held) until they complete. Connect is IORING_OP_CONNECT.
 * After close nothing calls back and the chain is not touched; state the kernel may still
 * read is freed when the last SQE of the send completes. */
#include "io/uring_priv.h"

#include "core/log.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define KBIT(kind) ((uint8_t)(1u << ((kind) - BST_UK_SEND)))

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

static void stash_push(bst_sock *s, bst_ubuf *b)
{
	b->next = NULL;
	if (s->u.st_tail != NULL)
		s->u.st_tail->next = b;
	else
		s->u.st_head = b;
	s->u.st_tail = b;
}

static bst_ubuf *stash_pop(bst_sock *s)
{
	bst_ubuf *b = s->u.st_head;
	if (b != NULL) {
		s->u.st_head = b->next;
		if (s->u.st_head == NULL)
			s->u.st_tail = NULL;
	}
	return b;
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

static void cancel_r(bst_uring *u, bst_sock *s)
{
	if (s->u.r_live) {
		bst_uring_cancel_(u, bst_uring_ud_(s->u.r_acc ? BST_UK_ACCEPT : BST_UK_RECV, s,
						   s->u.r_tag));
		s->u.r_live = false;
	}
	s->u.r_wait = false;
}

/* EOF (0) or an error: the stream ends until the next start. */
static void recv_end(bst_uring *u, bst_sock *s, int err)
{
	s->recv_on = false;
	cancel_r(u, s);
	s->recv_cb(s->recv_ud, NULL, err);
}

static void rearm_recv(bst_uring *u, bst_sock *s)
{
	if (arm_recv(u, s) != 0)
		recv_end(u, s, -EIO);
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
		return;
	}
	int res = e->res;
	if (res > 0 && b != NULL) {
		if (may_deliver(s)) {
			s->recv_cb(s->recv_ud, bst_ubufs_hand_(u, b), 0);
		} else {
			stash_push(s, b); /* stopped, or older data still to deliver */
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
			return; /* our cancel: stop or close */
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

static void deliver_stash(bst_uring *u, bst_sock *s)
{
	while (!s->closed && s->recv_on && !stash_empty(s)) {
		if (!bst_uring_budget_(u, s, BST_RECV_BUDGET)) {
			list_pend(u, s);
			return;
		}
		bst_ubuf *b = stash_pop(s);
		if (b != NULL) {
			s->recv_cb(s->recv_ud, bst_ubufs_hand_(u, b), 0);
			continue;
		}
		int end = s->u.st_end;
		s->u.st_end = 0;
		recv_end(u, s, end == 1 ? 0 : end);
		return;
	}
	if (!s->closed && s->recv_on && !s->u.r_live && !s->u.r_pend && stash_empty(s))
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
	cancel_r(s->loop->be, s);
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

void bst_uring_accept_cqe_(bst_uring *u, bst_sock *s, const bst_ucqe *e, bool last)
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
		bool ok = getpeername(res, (struct sockaddr *)&ss, &sl) == 0 &&
			  bst_net_peer_(&ss, &peer);
		s->acc_cb(s->acc_ud, res, ok ? &peer : NULL, 0);
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

static int ur_accept_start(bst_sock *ls)
{
	return arm_accept(ls->loop->be, ls);
}

/* ---- send ---- */

static void send_cleanup(bst_uring *u, bst_sock *s)
{
	if (s->u.sctx != NULL) {
		bst_slab_put(u->sends, s->u.sctx);
		s->u.sctx = NULL;
	}
	bst_upipe_put_(u, s->u.pipe, s->u.pipe_fill == 0);
	s->u.pipe = NULL;
	s->u.pipe_fill = 0;
	if (s->u.fdup >= 0) {
		close(s->u.fdup);
		s->u.fdup = -1;
	}
	s->u.zc_hold = 0;
	s->u.s_kinds = 0;
	s->u.s_pollout = false;
}

static void send_done(bst_uring *u, bst_sock *s, int err)
{
	send_cleanup(u, s);
	bst_net_send_finish_(s, err);
}

static void consume(bst_sock *s, size_t n)
{
	bst_chain_consume(s->send_chain, n);
	s->send_bytes += n;
}

static void sprep(bst_uring *u, struct io_uring_sqe *sqe, unsigned kind, bst_sock *s)
{
	bst_uring_prep_(u, sqe, kind, s, s->u.s_tag);
	s->u.s_out++;
	s->u.s_kinds |= KBIT(kind);
	if (kind == BST_UK_SPLICE_IN || kind == BST_UK_SPLICE_OUT)
		s->u.late++;
}

static int pump_file(bst_uring *u, bst_sock *s, int fd, off_t off, off_t flen, size_t budget)
{
	int err = 0;
	if (s->u.pipe == NULL && (s->u.pipe = bst_upipe_get_(u, &err)) == NULL)
		return err;
	size_t chunk = (uint64_t)flen > BST_SEND_CHUNK ? BST_SEND_CHUNK : (size_t)flen;
	if (chunk > s->u.pipe->cap)
		chunk = s->u.pipe->cap;
	if (chunk > budget)
		chunk = budget;
	if (bst_net_readahead_(s, fd, off, chunk))
		return 0; /* cold: the pool reads ahead, send_kick continues */
	if (s->u.fdup < 0 || s->u.fdup_src != fd) {
		if (s->u.fdup >= 0)
			close(s->u.fdup);
		s->u.fdup = fcntl(fd, F_DUPFD_CLOEXEC, 0);
		if (s->u.fdup < 0)
			return -errno;
		s->u.fdup_src = fd;
	}
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 2);
	if (sqe == NULL)
		return -EBUSY;
	io_uring_prep_splice(sqe, s->u.fdup, off, s->u.pipe->wr, -1, (unsigned)chunk,
			     SPLICE_F_NONBLOCK);
	sqe->flags |= IOSQE_IO_LINK; /* a short read breaks the link: the rest goes next round */
	sprep(u, sqe, BST_UK_SPLICE_IN, s);
	sqe = io_uring_get_sqe(&u->ring);
	io_uring_prep_splice(sqe, s->u.pipe->rd, -1, s->fd, -1, (unsigned)chunk, SPLICE_F_NONBLOCK);
	sprep(u, sqe, BST_UK_SPLICE_OUT, s);
#ifdef BST_TEST
	bst_test_uring_splices++;
	bst_test_uring_splice_outs++;
#endif
	return 0;
}

static int pump_mem(bst_uring *u, bst_sock *s, size_t budget)
{
	bst_upipe_put_(u, s->u.pipe, true); /* empty here: the pipe is only kept for files */
	s->u.pipe = NULL;
	if (s->u.sctx == NULL && (s->u.sctx = bst_slab_get(u->sends)) == NULL)
		return -ENOMEM;
	bst_usend *x = s->u.sctx;
	int cnt = bst_chain_to_iov(s->send_chain, x->iov, (int)BST_URING_IOV);
	size_t total = 0;
	for (int i = 0; i < cnt; i++) {
		if (x->iov[i].iov_len >= budget - total) {
			x->iov[i].iov_len = budget - total;
			total = budget;
			cnt = i + 1;
			break;
		}
		total += x->iov[i].iov_len;
	}
	memset(&x->mh, 0, sizeof x->mh);
	x->mh.msg_iov = x->iov;
	x->mh.msg_iovlen = (__typeof__(x->mh.msg_iovlen))cnt; /* int on musl, size_t on glibc */
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	if (sqe == NULL)
		return -EBUSY;
	s->u.s_zc = u->zc_min != 0 && total >= u->zc_min && (u->feat & BST_URF_SENDMSG_ZC);
	if (s->u.s_zc) {
		io_uring_prep_sendmsg_zc(sqe, s->fd, &x->mh, MSG_NOSIGNAL);
#ifdef BST_TEST
		bst_test_uring_zc++;
#endif
	} else {
		io_uring_prep_sendmsg(sqe, s->fd, &x->mh, MSG_NOSIGNAL);
	}
	sprep(u, sqe, BST_UK_SEND, s);
	return 0;
}

/* One round: prepares the next SQEs. 0: in flight (or a readahead job owns the send),
 * 1: nothing left to send, < 0: error. Called only with nothing of the send in flight. */
static int pump(bst_uring *u, bst_sock *s)
{
	size_t budget = bst_net_send_budget_();
	s->u.s_kinds = 0;
	if (s->u.pipe_fill > 0) { /* file bytes in the pipe go to the socket first */
		unsigned need = s->u.s_pollout ? 2 : 1;
		struct io_uring_sqe *sqe = bst_uring_sqe_(u, need);
		if (sqe == NULL)
			return -EBUSY;
		if (s->u.s_pollout) {
			io_uring_prep_poll_add(sqe, s->fd, POLLOUT);
			sqe->flags |= IOSQE_IO_LINK;
			sprep(u, sqe, BST_UK_SPOLL, s);
			sqe = io_uring_get_sqe(&u->ring);
			s->u.s_pollout = false;
		}
		io_uring_prep_splice(sqe, s->u.pipe->rd, -1, s->fd, -1, (unsigned)s->u.pipe_fill,
				     SPLICE_F_NONBLOCK);
		sprep(u, sqe, BST_UK_SPLICE_OUT, s);
#ifdef BST_TEST
		bst_test_uring_splice_outs++;
#endif
		return 0;
	}
	if (bst_chain_len(s->send_chain) == 0)
		return 1;
	int fd;
	off_t off, flen;
	if (bst_chain_front_file(s->send_chain, &fd, &off, &flen))
		return pump_file(u, s, fd, off, flen, budget);
	return pump_mem(u, s, budget);
}

static void pump_or_finish(bst_uring *u, bst_sock *s)
{
	int r = pump(u, s);
	if (r != 0)
		send_done(u, s, r == 1 ? 0 : r);
}

void bst_uring_send_cqe_(bst_uring *u, bst_sock *s, unsigned kind, const bst_ucqe *e, bool last)
{
	if (last) {
		s->u.s_out--;
		if (kind == BST_UK_SPLICE_IN || kind == BST_UK_SPLICE_OUT)
			s->u.late--;
	}
	bool live = !s->closed && !u->draining && s->send_on &&
		    (uint16_t)(e->ud >> 48) == s->u.s_tag;
	int res = e->res, err = 0;
	bool sock_err = false;
	switch (kind) {
	case BST_UK_SEND:
		if (e->flags & IORING_CQE_F_NOTIF) { /* zero-copy: the kernel is done with the pages */
			if (live)
				consume(s, s->u.zc_hold);
			s->u.zc_hold = 0;
		} else if (res > 0) {
			if (!last)
				s->u.zc_hold += (size_t)res; /* consumed at the notification */
			else if (live)
				consume(s, (size_t)res);
		} else if (res < 0 && res != -EAGAIN && res != -EINTR) {
			err = res;
			sock_err = true;
		}
		break;
	case BST_UK_SPLICE_IN:
		if (res > 0)
			s->u.pipe_fill += (size_t)res;
		else if (res != -EAGAIN && res != -EINTR)
			err = res == 0 ? -EIO : res; /* 0: the file ended before its segment */
		break;
	case BST_UK_SPLICE_OUT:
		if (res > 0) {
			s->u.pipe_fill -= (size_t)res;
			if (live)
				consume(s, (size_t)res);
		} else if (res == -EAGAIN || res == 0) {
			s->u.s_pollout = true; /* the socket is full */
		} else if (res != -ECANCELED && res != -EINTR) { /* ECANCELED: the link broke */
			err = res;
			sock_err = true;
		}
		break;
	case BST_UK_SPOLL:
		if (res < 0 && res != -ECANCELED) {
			err = res;
			sock_err = true;
		}
		break;
	case BST_UK_CONNECT:
		err = res;
		break;
	default: /* BST_UK_NOP */
		break;
	}
	if (sock_err && err != -EPIPE)
		s->last_err = -err;
	if (err != 0 && s->u.s_err == 0)
		s->u.s_err = err;
	if (s->u.s_out > 0)
		return;
	if (!live) {
		if (s->closed || u->draining)
			send_cleanup(u, s);
		return;
	}
	if (kind == BST_UK_CONNECT) {
		send_done(u, s, s->u.s_err);
		return;
	}
	if (s->u.s_err != 0) {
		send_done(u, s, bst_net_send_err_(s, -s->u.s_err));
		return;
	}
	pump_or_finish(u, s);
}

static int ur_send_start(bst_sock *s)
{
	bst_uring *u = s->loop->be;
	s->u.s_tag++;
	s->u.s_err = 0;
	int r = pump(u, s);
	if (r == 0)
		return 0;
	if (r < 0) {
		send_cleanup(u, s);
		return r;
	}
	/* empty chain: still completes from the loop */
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	if (sqe == NULL)
		return -EBUSY;
	io_uring_prep_nop(sqe);
	sprep(u, sqe, BST_UK_NOP, s);
	return 0;
}

static void ur_send_kick(bst_sock *s)
{
	if (s->u.s_out == 0)
		pump_or_finish(s->loop->be, s);
}

static int ur_connect(bst_sock *s, const struct sockaddr_storage *to, socklen_t len)
{
	bst_uring *u = s->loop->be;
	if (s->u.sctx == NULL && (s->u.sctx = bst_slab_get(u->sends)) == NULL)
		return -ENOMEM;
	memcpy(&s->u.sctx->addr, to, sizeof *to); /* read by the kernel when it issues */
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	if (sqe == NULL) {
		send_cleanup(u, s);
		return -EBUSY;
	}
	io_uring_prep_connect(sqe, s->fd, (struct sockaddr *)&s->u.sctx->addr, len);
	s->u.s_tag++;
	s->u.s_err = 0;
	sprep(u, sqe, BST_UK_CONNECT, s);
	return 0;
}

/* ---- close ---- */

void bst_uring_net_detach_(bst_uring *u, bst_sock *s)
{
	cancel_r(u, s);
	bst_ubuf *b;
	while ((b = stash_pop(s)) != NULL)
		bst_ubufs_recycle_(u, b);
	s->u.st_end = 0;
	if (s->u.s_out == 0) {
		send_cleanup(u, s);
		return;
	}
	for (unsigned k = BST_UK_SEND; k <= BST_UK_NOP; k++)
		if (s->u.s_kinds & KBIT(k))
			bst_uring_cancel_(u, bst_uring_ud_(k, s, s->u.s_tag));
}

const bst_net_ops bst_uring_net_ops_ = {
	.accept_start = ur_accept_start,
	.recv_start = ur_recv_start,
	.recv_stop = ur_recv_stop,
	.send_start = ur_send_start,
	.connect = ur_connect,
	.send_kick = ur_send_kick,
};

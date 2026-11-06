/* io_uring stream output behind net.h's API: bst_io_send and bst_io_connect.
 *
 * One round at a time, at most the send budget per round (one round per dispatch).
 * Memory segments go with SENDMSG, or SENDMSG_ZC from uring_send_zc_min bytes: the chain
 * is consumed, and the reference this file holds on each buffer dropped, only when the
 * kernel's notification says the pages are free; closing with such pages still queued
 * aborts the connection, so rewritten caller memory never reaches the peer. File segments
 * go with SPLICE file -> pipe linked to SPLICE pipe -> socket, after the same residency
 * probe and pool readahead as epoll (per send window), so a cold file never stalls the
 * loop or an io-wq worker. A full socket makes the splice return -EAGAIN; the next round
 * links POLL_ADD(POLLOUT) before it. Splices name their fds only when they run, so they use
 * a dup of the file fd and keep the socket fd open (fd_held) until they complete. Without a
 * pipe (splice refused by the filesystem, fds or pipe memory short, the per-loop cap) a
 * file segment goes with POLL_ADD(POLLOUT) then sendfile on the loop thread. Connect is
 * IORING_OP_CONNECT. After close nothing calls back and the chain is not touched; state
 * the kernel may still read is freed when the last SQE of the send completes. */
#include "io/uring_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <unistd.h>

#define KBIT(kind) ((uint8_t)(1u << ((kind) - BST_UK_SEND)))

/* ---- send ---- */

static bst_usend *new_sctx(bst_uring *u)
{
	bst_usend *x = bst_slab_get(u->sends); /* contents unspecified */
	if (x != NULL)
		x->nzbuf = 0;
	return x;
}

/* Zero-copy: the kernel no longer reads the pages, drop the references that kept them. */
static void zc_release(bst_sock *s)
{
	bst_usend *x = s->u.sctx;
	if (x == NULL)
		return;
	for (unsigned i = 0; i < x->nzbuf; i++)
		bst_buf_unref(x->zbuf[i]);
	x->nzbuf = 0;
}

static void send_cleanup(bst_uring *u, bst_sock *s)
{
	zc_release(s);
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
	s->u.sf = s->u.sf_ready = false;
	s->u.ra_hi = 0;
	s->u.ra_ok = false;
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

static int pump(bst_uring *u, bst_sock *s);

/* File segments without a pipe: POLL_ADD(POLLOUT), then sendfile on the loop thread after
 * the same residency probe as epoll (a cold chunk is read ahead on the pool first). */
static int pump_sendfile(bst_uring *u, bst_sock *s, int fd, off_t off, size_t chunk)
{
	if (!s->u.sf_ready) {
		if (bst_net_readahead_(s, fd, off, chunk))
			return 0;
		struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
		if (sqe == NULL)
			return -EBUSY;
		io_uring_prep_poll_add(sqe, s->fd, POLLOUT);
		sprep(u, sqe, BST_UK_SFPOLL, s);
		return 0;
	}
	s->u.sf_ready = false;
	off_t o = off; /* no SIGPIPE: the process ignores it (bst_io_ignore_sigpipe) */
	ssize_t n = sendfile(s->fd, fd, &o, chunk);
#ifdef BST_TEST
	bst_test_uring_sendfiles++;
#endif
	if (n > 0) {
		consume(s, (size_t)n);
		return pump(u, s); /* the next round only prepares: one write per round */
	}
	if (n == 0)
		return -EIO; /* the file ended before its segment */
	int e = errno;
	if (e == EAGAIN || e == EINTR)
		return pump(u, s);
	if (e != EPIPE)
		s->last_err = e;
	return bst_net_send_err_(s, e);
}

/* Cold pages are probed and read ahead per send window (BST_SEND_CHUNK, as epoll's
 * sendfile), then spliced in pipe-sized pieces without probing again inside the window. */
static bool file_cold(bst_sock *s, int fd, off_t off, size_t window)
{
	bool inside = s->u.ra_hi != 0 && s->u.ra_fd == fd && off >= s->u.ra_lo && off < s->u.ra_hi;
	if (s->u.ra_ok && inside)
		return false;
	if (s->ra_skip) { /* the job for the window just finished (a retry timer never sets it) */
		s->ra_skip = false;
		s->u.ra_ok = inside;
		return false;
	}
	s->u.ra_ok = false;
	s->u.ra_hi = 0;
	if (!bst_net_readahead_(s, fd, off, window))
		return false;
	s->u.ra_fd = fd;
	s->u.ra_lo = off;
	s->u.ra_hi = off + (off_t)window;
	return true;
}

static int pump_file(bst_uring *u, bst_sock *s, int fd, off_t off, off_t flen, size_t budget)
{
	size_t chunk = (uint64_t)flen > BST_SEND_CHUNK ? BST_SEND_CHUNK : (size_t)flen;
	if (chunk > budget)
		chunk = budget;
	if (s->u.sf) { /* this file cannot be spliced */
		bst_upipe_put_(u, s->u.pipe, s->u.pipe_fill == 0);
		s->u.pipe = NULL;
		return pump_sendfile(u, s, fd, off, chunk);
	}
	if (s->u.pipe == NULL) {
		int err = 0;
		s->u.pipe = bst_upipe_get_(u, &err);
		if (s->u.pipe == NULL) {
			/* Out of fds, pipe memory or the cap on pipes in use: sendfile this round. */
			if (err == -EMFILE || err == -ENFILE || err == -ENOBUFS || err == -EBUSY)
				return pump_sendfile(u, s, fd, off, chunk);
			return err;
		}
	}
	if (file_cold(s, fd, off, chunk))
		return 0; /* cold: the pool reads ahead, send_kick continues */
	if (chunk > s->u.pipe->cap)
		chunk = s->u.pipe->cap;
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
	unsigned fl = SPLICE_F_NONBLOCK;
#ifdef BST_TEST
	if (bst_test_uring_splice_einval)
		fl |= 0x40000000u; /* not a splice flag: the kernel answers -EINVAL */
#endif
	io_uring_prep_splice(sqe, s->u.fdup, off, s->u.pipe->wr, -1, (unsigned)chunk, fl);
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
	if (s->u.sctx == NULL && (s->u.sctx = new_sctx(u)) == NULL)
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
		/* The kernel reads these pages until the notification, maybe after close: hold
		 * the buffers until then, whatever the caller does with its own references. */
		x->nzbuf = (unsigned)bst_chain_front_bufs(s->send_chain, x->zbuf, cnt);
		for (unsigned i = 0; i < x->nzbuf; i++)
			bst_buf_ref(x->zbuf[i]);
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
	s->u.s_zc = false;
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
	if (kind == BST_UK_SEND && last && s->u.s_zc)
		zc_release(s); /* after close and during drain too */
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
		else if (res == -EINVAL || res == -EOPNOTSUPP)
			s->u.sf = true; /* no splice_read on this filesystem: sendfile from now on */
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
	case BST_UK_SFPOLL:
		if (res > 0)
			s->u.sf_ready = true; /* POLLERR too: the sendfile reports the error */
		else if (res < 0 && res != -ECANCELED) {
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

int bst_uring_send_start_(bst_sock *s)
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

void bst_uring_send_kick_(bst_sock *s)
{
	if (s->u.s_out == 0)
		pump_or_finish(s->loop->be, s);
}

int bst_uring_connect_(bst_sock *s, const struct sockaddr_storage *to, socklen_t len)
{
	bst_uring *u = s->loop->be;
	if (s->u.sctx == NULL && (s->u.sctx = new_sctx(u)) == NULL)
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

bool bst_uring_send_detach_(bst_uring *u, bst_sock *s)
{
	if (s->u.s_out == 0) {
		send_cleanup(u, s);
		return true;
	}
	bool ok = true;
	for (unsigned k = BST_UK_SEND; k <= BST_UK_SFPOLL; k++)
		if (s->u.s_kinds & KBIT(k))
			ok &= bst_uring_cancel_(u, bst_uring_ud_(k, s, s->u.s_tag));
	/* Zero-copy pages still queued in TCP would go out after close, from memory the caller
	 * may rewrite: abort the connection instead (RST drops the send queue). */
	if (s->u.s_zc && !s->borrowed) {
		struct linger lg = {.l_onoff = 1, .l_linger = 0};
		(void)setsockopt(s->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
	}
	return ok;
}

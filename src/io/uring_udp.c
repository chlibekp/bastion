/* io_uring UDP behind io/udp.h: multishot IORING_OP_RECVMSG and chained IORING_OP_SENDMSG.
 *
 * Receive. One multishot RECVMSG per socket takes slots from the UDP provided-buffer group
 * (BST_URING_UGID): slots of BST_UDP_SLOT_SIZE, so a GRO-coalesced datagram (up to 64 KiB)
 * is never cut by the loop's 16 KiB recv slots. A completion is a record, [io_uring_recvmsg_out]
 * [name][control][payload], with the name and control regions at the sizes in the socket's
 * template msghdr (rmh). A payload up to BST_UDP_COPY_MAX bytes, or any payload once half
 * the slots are out, is copied into a buffer of its own and the slot recycled at once (the
 * TCP copy-out rule, net.h); a larger one is handed to the caller as a sub-range of the
 * slot, which goes back to the ring at the caller's unref. Datagrams collect per socket
 * and are delivered as one batch at the end of the dispatch (bst_uring_udp_flush_), or when
 * BST_UDP_BATCH have gathered. A socket over its per-dispatch budget has its multishot
 * cancelled and its carried completions copied out under pressure, as for TCP. The kernel
 * ending the multishot (CQ full, no slot) is answered with a re-arm, at once or, with no
 * slot free, when one comes back (bst_uring_udp_prewait_).
 *
 * Send. A round is up to BST_UDP_CHAIN SENDMSG SQEs linked in order (the planner is
 * udp.c's): a failed one cancels the rest, so the ones that went out are exactly a prefix,
 * and the cursor advances by that count. -EAGAIN submits POLL_ADD(POLLOUT) and repeats the
 * round; EIO on a GSO message turns GSO off and replans. The packets' payload stays the
 * caller's memory: close cancels the SQEs and flushes before returning, like TCP sends. */
#include "io/uring_priv.h"

#include "core/log.h"

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* ---- the UDP slot group ---- */

static unsigned char *uslot(const bst_uudp *b, unsigned bid)
{
	return b->mem + (size_t)bid * BST_UDP_SLOT_SIZE;
}

static void uring_add(bst_uudp *b, unsigned bid)
{
	io_uring_buf_ring_add(b->br, uslot(b, bid), BST_UDP_SLOT_SIZE, (unsigned short)bid,
			      io_uring_buf_ring_mask(b->n), 0);
	io_uring_buf_ring_advance(b->br, 1);
}

int bst_uudp_init_(bst_uring *u, unsigned n, bst_err *err)
{
	if (n > BST_URING_UDP_BUFS_MAX)
		n = BST_URING_UDP_BUFS_MAX;
	unsigned p2 = 2;
	while (p2 < n)
		p2 <<= 1;
	n = p2;
	bst_uudp *b = calloc(1, sizeof *b);
	if (b == NULL)
		goto nomem;
	b->mem = malloc((size_t)n * BST_UDP_SLOT_SIZE);
	b->hdr = calloc(n, sizeof *b->hdr);
	u->ub = b; /* from here bst_uudp_free_ cleans up */
	if (b->mem == NULL || b->hdr == NULL)
		goto nomem;
	int rc = 0;
	b->br = io_uring_setup_buf_ring(&u->ring, n, BST_URING_UGID, 0, &rc);
	if (b->br == NULL) {
		bst_err_set(err, "io_uring UDP provided-buffer ring: %s", strerror(-rc));
		return rc != 0 ? rc : -ENOMEM;
	}
	b->n = n;
	for (unsigned i = 0; i < n; i++) {
		b->hdr[i].u = u;
		b->hdr[i].bid = (uint16_t)i;
		io_uring_buf_ring_add(b->br, uslot(b, i), BST_UDP_SLOT_SIZE, (unsigned short)i,
				      io_uring_buf_ring_mask(n), (int)i);
	}
	io_uring_buf_ring_advance(b->br, (int)n);
	return 0;
nomem:
	bst_err_set(err, "out of memory");
	return -ENOMEM;
}

void bst_uudp_free_(bst_uring *u)
{
	bst_uudp *b = u->ub;
	if (b == NULL || u->leak) /* the kernel may still write into the slots */
		return;
	if (b->br != NULL &&
	    io_uring_free_buf_ring(&u->ring, b->br, b->n, BST_URING_UGID) != 0)
		munmap(b->br, (size_t)b->n * sizeof(struct io_uring_buf));
	free(b->mem);
	free(b->hdr);
	free(b);
	u->ub = NULL;
}

static bst_uubuf *utake(bst_uudp *b, unsigned bid)
{
	return bid < b->n ? &b->hdr[bid] : NULL;
}

static void urecycle(bst_uring *u, bst_uubuf *s)
{
	if (s == NULL)
		return;
	uring_add(u->ub, s->bid);
	u->ub->taken--;
	u->ub->returned = true;
}

static void uslot_release(bst_buf *b, void *ctx)
{
	bst_uring *u = ctx;
	u->ub->bout--;
	urecycle(u, (bst_uubuf *)b); /* b is the header's first member */
}

static bst_buf *uhand(bst_uring *u, bst_uubuf *s)
{
	bst_buf_init(&s->b, uslot(u->ub, s->bid), BST_UDP_SLOT_SIZE, uslot_release, u);
	u->ub->bout++;
	return &s->b;
}

static bool upressed(const bst_uudp *b)
{
	return b->taken >= b->n / 2;
}

static unsigned uavail(const bst_uudp *b)
{
	return b->n - b->taken;
}

/* ---- lists: each membership holds an inflight ---- */

static void list_wait(bst_uring *u, bst_sock *s)
{
	bst_udp *x = s->udp;
	s->u.r_wait = true;
	if (x->waiting)
		return;
	x->waiting = true;
	x->wnext = u->ub->wait;
	u->ub->wait = s;
	s->inflight++;
}

static void list_flush(bst_uring *u, bst_sock *s)
{
	bst_udp *x = s->udp;
	if (x->flisted)
		return;
	x->flisted = true;
	x->fnext = u->ub->flush;
	u->ub->flush = s;
	s->inflight++;
}

void bst_uring_udp_drain_(bst_uring *u)
{
	bst_uudp *b = u->ub;
	if (b == NULL)
		return;
	while (b->wait != NULL) {
		bst_sock *s = b->wait;
		b->wait = s->udp->wnext;
		s->udp->waiting = false;
		s->u.r_wait = false;
		bst_sock_release_(s);
	}
	while (b->flush != NULL) {
		bst_sock *s = b->flush;
		bst_udp *x = s->udp;
		b->flush = x->fnext;
		x->flisted = false;
		for (int i = 0; i < x->npend; i++)
			bst_buf_unref(x->pend[i].buf);
		x->npend = 0;
		bst_sock_release_(s);
	}
}

/* ---- receive ---- */

static int arm_urecv(bst_uring *u, bst_sock *s)
{
	bst_udp *x = s->udp;
	if (s->u.r_live)
		return 0;
	if (uavail(u->ub) == 0) {
		list_wait(u, s);
		return 0;
	}
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	if (sqe == NULL)
		return -EBUSY;
	memset(&x->rmh, 0, sizeof x->rmh);
	x->rmh.msg_namelen = BST_UDP_RNAME;
	x->rmh.msg_controllen = BST_UDP_RCTL;
	io_uring_prep_recvmsg_multishot(sqe, s->fd, &x->rmh, 0);
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = BST_URING_UGID;
	uint16_t tag = (uint16_t)s->recv_epoch;
	bst_uring_prep_(u, sqe, BST_UK_URECV, s, tag);
	s->u.r_live = true;
	s->u.r_mshot = true;
	s->u.r_acc = false;
	s->u.r_tag = tag;
	return 0;
}

/* Cancel the multishot; its tag is retired so a re-arm is never hit by this cancel. */
static bool cancel_r(bst_uring *u, bst_sock *s)
{
	bool ok = true;
	if (s->u.r_live) {
		ok = bst_uring_cancel_(u, bst_uring_ud_(BST_UK_URECV, s, s->u.r_tag));
		s->u.r_live = false;
		s->recv_epoch++;
	}
	s->u.r_wait = false;
	s->u.r_parked = false;
	return ok;
}

static void flush_one(bst_sock *s)
{
	bst_udp *x = s->udp;
	int n = x->npend;
	x->npend = 0;
	if (n == 0)
		return;
	if (s->closed || !x->on) {
		for (int i = 0; i < n; i++)
			bst_buf_unref(x->pend[i].buf);
		return;
	}
	x->cb(x->cb_ud, x->pend, n, 0);
}

void bst_uring_udp_flush_(bst_uring *u)
{
	bst_uudp *b = u->ub;
	if (b == NULL)
		return;
	while (b->flush != NULL) {
		bst_sock *s = b->flush;
		b->flush = s->udp->fnext;
		s->udp->flisted = false;
		flush_one(s);
		bst_sock_release_(s);
	}
}

static void urecv_end(bst_uring *u, bst_sock *s, int err)
{
	bst_udp *x = s->udp;
	flush_one(s); /* what was collected before the error comes first */
	if (s->closed || !x->on)
		return;
	x->on = false;
	(void)cancel_r(u, s);
	x->cb(x->cb_ud, NULL, 0, err);
}

static void rearm(bst_uring *u, bst_sock *s)
{
	if (arm_urecv(u, s) != 0)
		urecv_end(u, s, -EIO);
}

/* One datagram record: rec[0, reclen), in a ring slot (sb) or a copy of it (copy). */
static void process(bst_uring *u, bst_sock *s, const unsigned char *rec, size_t reclen,
		    bst_buf *copy, bst_uubuf *sb)
{
	bst_udp *x = s->udp;
	const size_t hdr = sizeof(struct io_uring_recvmsg_out);
	const size_t noff = hdr, coff = hdr + x->rmh.msg_namelen;
	const size_t poff = coff + x->rmh.msg_controllen;
	struct io_uring_recvmsg_out o;
	bst_udp_msg m;
	bst_udp_meta meta;
	memset(&m, 0, sizeof m);
	bool ok = reclen >= poff;
	if (ok)
		memcpy(&o, rec, sizeof o);
	size_t plen = ok ? reclen - poff : 0;
	if (!ok) {
		x->st.rx_badctl++;
	} else if ((o.flags & MSG_TRUNC) != 0 || plen > x->cap) {
		x->st.rx_trunc++;
		ok = false;
	} else if (plen == 0) {
		x->st.rx_empty++;
		ok = false;
	} else if ((o.flags & MSG_CTRUNC) != 0 || o.controllen > x->rmh.msg_controllen ||
		   !bst_udp_parse_cmsg_(rec + coff, o.controllen, &meta) ||
		   !bst_udp_name_(rec + noff,
				  o.namelen < x->rmh.msg_namelen ? o.namelen : x->rmh.msg_namelen,
				  &m.src)) {
		x->st.rx_badctl++;
		ok = false;
	}
	if (ok) {
		if (copy != NULL) {
			m.buf = bst_udp_sub_buf_(copy, copy->data + poff, plen);
			copy = NULL; /* its reference went to the sub-buffer */
		} else if (plen <= BST_UDP_COPY_MAX || upressed(u->ub)) {
			m.buf = bst_udp_copy_buf_(u->loop, plen);
			if (m.buf != NULL) {
				memcpy(m.buf->data, rec + poff, plen);
				m.buf->len = plen;
#ifdef BST_TEST
				bst_test_uring_udp_copies++;
#endif
			}
			urecycle(u, sb);
			sb = NULL;
		} else {
			bst_buf *p = uhand(u, sb);
			sb = NULL;
			m.buf = bst_udp_sub_buf_(p, p->data + poff, plen);
		}
		if (m.buf == NULL) {
			x->st.rx_nomem++;
			ok = false;
		}
	}
	urecycle(u, sb);
	bst_buf_unref(copy);
	if (!ok)
		return;
	bst_udp_fill_msg_(&m, &meta, plen);
	x->st.rx_dgrams++;
	x->pend[x->npend++] = m;
	if (x->npend == (int)BST_UDP_BATCH)
		flush_one(s);
	else
		list_flush(u, s);
}

void bst_uring_urecv_cqe_(bst_uring *u, bst_sock *s, const bst_ucqe *e, bool last)
{
	bst_udp *x = s->udp;
	bst_uubuf *b = NULL;
	if ((e->flags & IORING_CQE_F_BUFFER) && u->ub != NULL)
		b = utake(u->ub, e->flags >> IORING_CQE_BUFFER_SHIFT);
	bool cur = s->u.r_live && (uint16_t)(e->ud >> 48) == s->u.r_tag;
	if (cur && last)
		s->u.r_live = false;
	/* Ours: the live arm, or the one cancelled over budget whose carried completions are
	 * still to be delivered. Anything else is an arm that stop or a restart retired: its
	 * data and its errors are dropped, never given to the new stream. */
	bool ours = cur || (x != NULL && x->park_valid && (uint16_t)(e->ud >> 48) == x->park_tag);
	if (s->closed || u->draining || x == NULL || !x->on || !ours) {
		urecycle(u, b);
		bst_buf_unref(e->copy);
		return;
	}
	int res = e->res;
	if (res > 0 && (b != NULL || e->copy != NULL)) {
		const unsigned char *rec = e->copy != NULL ? e->copy->data : uslot(u->ub, b->bid);
		if (e->copy != NULL)
			e->copy->len = (size_t)res;
		process(u, s, rec, (size_t)res, e->copy, b);
	} else {
		urecycle(u, b);
		if (res == -ECANCELED)
			return; /* our cancel: stop, close or the budget */
#ifdef BST_TEST
		if (res == -ENOBUFS)
			bst_test_uring_udp_nobufs++;
#endif
		if (res == -ENOBUFS || res == -EINTR || res == -EAGAIN || bst_udp_transient_(-res)) {
			if (cur && last) {
				if (res == -ENOBUFS && uavail(u->ub) == 0)
					list_wait(u, s);
				else
					rearm(u, s);
			}
			return;
		}
		if (res >= 0)
			return; /* no buffer behind a positive result: nothing to deliver */
		urecv_end(u, s, res);
		return;
	}
	if (!s->closed && cur && last && x->on && !s->u.r_live)
		rearm(u, s); /* the kernel ended the multishot (CQ full) */
}

void bst_uring_udp_carry_(bst_uring *u, bst_sock *s, bst_ucqe *e)
{
	s->u.carried++;
#ifdef BST_TEST
	bst_test_uring_udp_carries++;
#endif
	if ((e->flags & IORING_CQE_F_BUFFER) && e->res > 0 && u->ub != NULL && upressed(u->ub)) {
		bst_uubuf *b = utake(u->ub, e->flags >> IORING_CQE_BUFFER_SHIFT);
		bst_buf *c = b != NULL ? bst_buf_new((size_t)e->res) : NULL;
		if (c != NULL) { /* the raw record: header, name, control and payload */
			memcpy(c->data, uslot(u->ub, b->bid), (size_t)e->res);
			c->len = (size_t)e->res;
			urecycle(u, b);
			e->copy = c;
			e->flags &= ~(uint32_t)IORING_CQE_F_BUFFER;
		}
	}
	/* Over budget: stop taking slots for s until its carry is delivered. */
	if (s->u.r_live && !s->closed) {
		s->udp->park_tag = s->u.r_tag;
		s->udp->park_valid = true;
		(void)cancel_r(u, s);
		s->u.r_parked = true;
	}
}

void bst_uring_udp_uncarry_(bst_uring *u, bst_sock *s)
{
	if (s->u.carried > 0 || !s->u.r_parked)
		return;
	s->u.r_parked = false;
	if (!s->closed && s->udp != NULL && s->udp->on && !s->u.r_live)
		rearm(u, s);
}

void bst_uring_udp_prewait_(bst_uring *u)
{
	bst_uudp *b = u->ub;
	if (b == NULL || b->wait == NULL || !b->returned || uavail(b) == 0)
		return;
	b->returned = false;
	bst_sock *list = b->wait;
	b->wait = NULL;
	while (list != NULL) {
		bst_sock *s = list;
		bst_udp *x = s->udp;
		list = x->wnext;
		bool want = s->u.r_wait;
		x->waiting = false;
		s->u.r_wait = false;
		bst_sock_release_(s);
		if (want && !s->closed && x->on && !s->u.r_live && arm_urecv(u, s) != 0)
			list_wait(u, s); /* no SQE now: next time */
	}
}

static int ur_recv_start(bst_sock *s)
{
	bst_uring *u = s->loop->be;
	if (u->ub == NULL)
		return -ENOSYS; /* readiness path */
	return arm_urecv(u, s);
}

static void ur_recv_stop(bst_sock *s)
{
	(void)cancel_r(s->loop->be, s);
}

/* ---- send ---- */

static void send_finish(bst_sock *s, int err)
{
	bst_udp *x = s->udp;
	bst_done_cb cb = x->dcb;
	void *ud = x->dud;
	size_t n = x->bytes;
	x->send_on = false;
	x->phase = 0;
	x->pk = NULL;
	cb(ud, n, err); /* may start the next send, or close s */
}

static int submit_one(bst_uring *u, bst_sock *s, int phase)
{
	bst_udp *x = s->udp;
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, 1);
	if (sqe == NULL)
		return -EBUSY;
	if (phase == 2)
		io_uring_prep_poll_add(sqe, s->fd, POLLOUT);
	else
		io_uring_prep_nop(sqe);
	bst_uring_prep_(u, sqe, BST_UK_USEND, s, s->u.s_tag);
	x->us_out = 1;
	x->phase = phase;
	x->ok_n = 0;
	x->rerr = 0;
	return 0;
}

/* Plan and submit the next round: 0 once its SQEs are in. */
static int send_round(bst_uring *u, bst_sock *s)
{
	bst_udp *x = s->udp;
#ifdef BST_TEST
	bst_test_udp_rounds++;
	if (bst_test_udp_eagain > 0) { /* the socket is "full": wait for POLLOUT */
		bst_test_udp_eagain--;
		return submit_one(u, s, 2);
	}
#endif
	int max = (int)BST_UDP_CHAIN;
#ifdef BST_TEST
	if (bst_test_udp_send_limit != 0 && bst_test_udp_send_limit < (unsigned)max)
		max = (int)bst_test_udp_send_limit;
#endif
	int k = bst_udp_plan_(x, max);
#ifdef BST_TEST
	if (bst_test_udp_gso_eio > 0)
		for (int i = 0; i < k; i++)
			if (x->m[i].gso) { /* what precedes it goes out, then the kernel "fails" */
				if (i == 0) {
					bst_test_udp_gso_eio--;
					return submit_one(u, s, 3);
				}
				k = i;
				break;
			}
#endif
	struct io_uring_sqe *sqe = bst_uring_sqe_(u, (unsigned)k);
	if (sqe == NULL)
		return -EBUSY;
	for (int i = 0; i < k; i++) {
		if (i > 0)
			sqe = io_uring_get_sqe(&u->ring);
		io_uring_prep_sendmsg(sqe, s->fd, &x->m[i].mh, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (i < k - 1)
			sqe->flags |= IOSQE_IO_LINK; /* a failure cancels the rest: a prefix went out */
		bst_uring_prep_(u, sqe, BST_UK_USEND, s, s->u.s_tag);
	}
	x->us_out = (uint16_t)k;
	x->round_k = k;
	x->phase = 1;
	x->ok_n = 0;
	x->rerr = 0;
	return 0;
}

static void round_done(bst_uring *u, bst_sock *s)
{
	bst_udp *x = s->udp;
	int phase = x->phase, e = x->rerr;
	x->phase = 0;
	x->rerr = 0;
	if (phase == 1) {
		bst_udp_advance_(x, x->ok_n); /* x->m is still this round's plan */
		if (e == 0 && x->ok_n < x->round_k)
			e = -EIO; /* cancelled with no cause */
		if (e == -EAGAIN || e == -ENOBUFS) {
			int r = submit_one(u, s, 2); /* POLLOUT, then the round repeats */
			if (r != 0)
				send_finish(s, -EIO);
			return;
		}
		if (e == -EIO && x->m[x->ok_n].gso)
			bst_udp_gso_off_(x); /* replan: the same packet as plain datagrams */
		else if (e != 0) {
			send_finish(s, e);
			return;
		}
	} else if (phase == 3) {
		bst_udp_gso_off_(x); /* the injected EIO of the first (GSO) message */
	} else if (e != 0) {
		send_finish(s, e); /* the POLLOUT wait failed */
		return;
	}
	if (x->cur >= x->npk) {
		send_finish(s, 0);
		return;
	}
	if (send_round(u, s) != 0)
		send_finish(s, -EIO);
}

void bst_uring_usend_cqe_(bst_uring *u, bst_sock *s, const bst_ucqe *e, bool last)
{
	bst_udp *x = s->udp;
	if (last && x->us_out > 0)
		x->us_out--;
	bool live = !s->closed && !u->draining && x->send_on;
	int res = e->res;
	if (live) {
		if (x->phase == 1) {
			if (res > 0)
				x->ok_n++;
			else if (res != -ECANCELED && x->rerr == 0)
				x->rerr = res == 0 ? -EIO : res;
		} else if (x->phase == 2) {
			if (res < 0 && res != -ECANCELED)
				x->rerr = res;
		}
	}
	if (x->us_out > 0 || !live)
		return;
	round_done(u, s);
}

static int ur_send_start(bst_sock *s)
{
	bst_uring *u = s->loop->be;
	s->u.s_tag++;
	return send_round(u, s);
}

bool bst_uring_udp_sending_(const bst_sock *s)
{
	return s->udp != NULL && s->udp->us_out > 0;
}

/* ---- close ---- */

bool bst_uring_udp_detach_(bst_uring *u, bst_sock *s)
{
	bst_udp *x = s->udp;
	bool ok = cancel_r(u, s);
	for (int i = 0; i < x->npend; i++)
		bst_buf_unref(x->pend[i].buf);
	x->npend = 0;
	if (x->us_out > 0)
		ok &= bst_uring_cancel_(u, bst_uring_ud_(BST_UK_USEND, s, s->u.s_tag));
	return ok;
}

const bst_udp_ops bst_uring_udp_ops_ = {
	.recv_start = ur_recv_start,
	.recv_stop = ur_recv_stop,
	.send_start = ur_send_start,
};

#ifdef BST_TEST
/* Feed the handler a completion as if the kernel had posted it: a record in rec (raw, as
 * RECVMSG writes it) or an error res, with the given arm tag. last false keeps the live arm. */
void bst_test_uring_udp_inject(bst_sock *s, int res, bst_buf *rec, uint16_t tag, bool last)
{
	bst_uring *u = s->loop->be;
	bst_ucqe e = {.ud = bst_uring_ud_(BST_UK_URECV, s, tag), .res = res, .copy = rec};
	bst_uring_urecv_cqe_(u, s, &e, last);
	bst_uring_udp_flush_(u);
}
#endif

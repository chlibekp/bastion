/* Batched UDP I/O (header: io/udp.h): the API, control messages, send planning, and the
 * readiness path (recvmmsg/sendmmsg driven by the socket's POLLIN and POLLOUT slots). That
 * path is epoll's, and io_uring's when multishot RECVMSG or UDP slots are missing; the ring
 * path is uring_udp.c.
 *
 * Send planning is shared: a send is the packets in order, a cursor (packet, bytes sent
 * of it), and rounds that plan up to BST_UDP_BATCH messages from the cursor. A GSO packet is
 * one message, whole; with GSO off the same packet is a run of plain messages of gso_size.
 * A round that sent n messages advances the cursor by exactly those n, so a retry after
 * EAGAIN or an EIO fallback never repeats a datagram and never skips one. */
#include "io/udp_priv.h"

#include "core/log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#ifdef BST_TEST
unsigned bst_test_udp_gso_eio, bst_test_udp_send_limit, bst_test_udp_eagain, bst_test_udp_rounds;
unsigned bst_test_udp_budget;
#endif

/* readiness-path receive scratch: one recvmmsg's worth */
typedef struct bst_urx {
	struct mmsghdr mm[BST_UDP_BATCH];
	struct iovec iov[BST_UDP_BATCH];
	struct sockaddr_storage name[BST_UDP_BATCH];
	unsigned char ctl[BST_UDP_BATCH][BST_UDP_CTL] __attribute__((aligned(8)));
	bst_buf *buf[BST_UDP_BATCH];
} bst_urx;

/* ---- addresses and control messages ---- */

bool bst_udp_name_(const void *name, size_t len, bst_sockaddr *out)
{
	struct sockaddr_storage ss;
	if (len > sizeof ss)
		len = sizeof ss;
	memset(&ss, 0, sizeof ss);
	memcpy(&ss, name, len);
	if (len < sizeof(sa_family_t))
		return false;
	if ((ss.ss_family == AF_INET && len < sizeof(struct sockaddr_in)) ||
	    (ss.ss_family == AF_INET6 && len < sizeof(struct sockaddr_in6)))
		return false;
	if (!bst_net_peer_(&ss, out))
		return false;
	out->ip = bst_ip_canon(&out->ip);
	return true;
}

bool bst_udp_parse_cmsg_(const void *ctl, size_t len, bst_udp_meta *out)
{
	memset(out, 0, sizeof *out);
	if (len < sizeof(struct cmsghdr))
		return len == 0;
	/* ctl may be unaligned (io_uring puts it after the name): parse an aligned copy */
	unsigned char tmp[BST_UDP_CTL] __attribute__((aligned(8)));
	if (len > sizeof tmp)
		return false;
	memcpy(tmp, ctl, len);
	struct msghdr mh;
	memset(&mh, 0, sizeof mh);
	mh.msg_control = tmp;
	mh.msg_controllen = (__typeof__(mh.msg_controllen))len;
	const unsigned char *end = tmp + len;
	/* musl's CMSG_NXTHDR compares a size_t with a ptrdiff_t */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm != NULL; cm = CMSG_NXTHDR(&mh, cm)) {
		size_t cl = (size_t)cm->cmsg_len;
		if (cl < CMSG_LEN(0) || cl > (size_t)(end - (const unsigned char *)cm))
			return false;
		size_t dl = cl - CMSG_LEN(0);
		const unsigned char *d = CMSG_DATA(cm);
		if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO) {
			if (dl >= sizeof(struct in_pktinfo)) {
				struct in_pktinfo pi;
				memcpy(&pi, d, sizeof pi);
				memset(&out->dst, 0, sizeof out->dst);
				out->dst.ip.family = BST_IP_V4;
				memcpy(out->dst.ip.b, &pi.ipi_addr, 4);
				out->ifindex = (uint32_t)pi.ipi_ifindex;
				out->has_dst = true;
			}
		} else if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_PKTINFO) {
			if (dl >= sizeof(struct in6_pktinfo)) {
				struct in6_pktinfo pi;
				memcpy(&pi, d, sizeof pi);
				memset(&out->dst, 0, sizeof out->dst);
				out->dst.ip.family = BST_IP_V6;
				memcpy(out->dst.ip.b, &pi.ipi6_addr, 16);
				out->dst.ip = bst_ip_canon(&out->dst.ip);
				out->ifindex = (uint32_t)pi.ipi6_ifindex;
				out->has_dst = true;
			}
		} else if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_TOS) {
			if (dl == 1) /* the kernel gives a byte here */
				out->ecn = d[0] & 3u;
			else if (dl >= sizeof(int)) {
				int v;
				memcpy(&v, d, sizeof v);
				out->ecn = (uint8_t)((unsigned)v & 3u);
			}
		} else if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_TCLASS) {
			if (dl >= sizeof(int)) {
				int v;
				memcpy(&v, d, sizeof v);
				out->ecn = (uint8_t)((unsigned)v & 3u);
			}
		} else if (cm->cmsg_level == SOL_UDP && cm->cmsg_type == UDP_GRO) {
			if (dl >= sizeof(int)) {
				int v;
				memcpy(&v, d, sizeof v);
				out->gro = v > 0 ? (uint32_t)v : 0;
			} else if (dl == sizeof(uint16_t)) {
				uint16_t v;
				memcpy(&v, d, sizeof v);
				out->gro = v;
			}
		}
		/* anything else: skipped */
	}
#pragma GCC diagnostic pop
	return true;
}

void bst_udp_fill_msg_(bst_udp_msg *m, const bst_udp_meta *meta, size_t len)
{
	if (meta->has_dst)
		m->dst = meta->dst;
	m->ifindex = meta->ifindex;
	m->ecn = meta->ecn;
	/* 0, a size at or above the datagram, or one that cannot be a UDP payload: one segment */
	m->gro_segment_size = meta->gro == 0 || meta->gro >= len || meta->gro > 65535
				      ? 0 : (uint16_t)meta->gro;
}

size_t bst_udp_segment(const bst_udp_msg *m, size_t *off, const unsigned char **seg)
{
	size_t len = m->buf->len;
	if (*off >= len)
		return 0;
	size_t n = len - *off;
	if (m->gro_segment_size != 0 && n > m->gro_segment_size)
		n = m->gro_segment_size;
	*seg = m->buf->data + *off;
	*off += n;
	return n;
}

bool bst_udp_transient_(int e)
{
	return e == ECONNREFUSED || e == EHOSTUNREACH || e == ENETUNREACH || e == EHOSTDOWN ||
	       e == ENETDOWN || e == EPROTO || e == ENOPROTOOPT;
}

/* ---- buffers ---- */

bst_buf *bst_udp_copy_buf_(bst_loop *l, size_t len)
{
	return len <= BST_RECV_BUF_SIZE ? bst_net_rbuf_(l) : bst_buf_new(len);
}

static void sub_release(bst_buf *b, void *ctx)
{
	(void)b;
	bst_buf_unref(ctx);
}

bst_buf *bst_udp_sub_buf_(bst_buf *parent, void *data, size_t len)
{
	bst_buf *b = bst_buf_wrap(data, len, sub_release, parent);
	if (b == NULL) {
		bst_buf_unref(parent);
		return NULL;
	}
	b->len = len;
	return b;
}

/* ---- attach ---- */

static void warn_opt(const char *what, int e)
{
	bst_log(BST_LOG_WARN, "udp: %s is not available here (%s): off", what, strerror(e));
}

static int attach(bst_sock *s, const bst_udp_cfg *cfg)
{
	int type = 0, dom = 0;
	socklen_t tl = sizeof type, dl = sizeof dom;
	if (getsockopt(s->fd, SOL_SOCKET, SO_TYPE, &type, &tl) != 0 ||
	    getsockopt(s->fd, SOL_SOCKET, SO_DOMAIN, &dom, &dl) != 0)
		return -errno;
	if (type != SOCK_DGRAM || (dom != AF_INET && dom != AF_INET6))
		return -EINVAL;
	bst_udp *u = calloc(1, sizeof *u);
	if (u == NULL)
		return -ENOMEM;
	u->s = s;
	u->family = dom;
	bst_udp_cfg c = cfg != NULL ? *cfg : (bst_udp_cfg){0};
	int on = 1, rc = 0;
	/* An AF_INET6 socket also gets the IPv4 options: v4-mapped traffic carries those. */
	if (dom == AF_INET6) {
		if (setsockopt(s->fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof on) != 0 ||
		    setsockopt(s->fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof on) != 0)
			rc = -errno;
		(void)setsockopt(s->fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof on);
		(void)setsockopt(s->fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof on);
	} else if (setsockopt(s->fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof on) != 0 ||
		   setsockopt(s->fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof on) != 0) {
		rc = -errno;
	}
	if (rc != 0) {
		free(u);
		return rc;
	}
	if (c.gro) {
		if (setsockopt(s->fd, SOL_UDP, UDP_GRO, &on, sizeof on) == 0)
			u->gro = true;
		else
			warn_opt("UDP_GRO", errno);
	}
	if (c.gso) {
		int v = 0;
		socklen_t vl = sizeof v;
		if (getsockopt(s->fd, SOL_UDP, UDP_SEGMENT, &v, &vl) == 0)
			u->gso = true;
		else
			warn_opt("UDP_SEGMENT", errno);
	}
	if (c.rcvbuf > 0) {
		int v = c.rcvbuf > (unsigned)INT32_MAX ? INT32_MAX : (int)c.rcvbuf;
		if (setsockopt(s->fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof v) != 0)
			warn_opt("rcvbuf", errno);
	}
	int tos = 0;
	socklen_t tsl = sizeof tos;
	if (dom == AF_INET6 ? getsockopt(s->fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, &tsl) != 0
			    : getsockopt(s->fd, IPPROTO_IP, IP_TOS, &tos, &tsl) != 0)
		tos = 0;
	u->base_tos = tos < 0 ? 0 : tos;
	size_t md = c.max_dgram != 0 ? c.max_dgram : BST_UDP_MAX_DGRAM;
	if (md > BST_UDP_GRO_BUF)
		md = BST_UDP_GRO_BUF;
	u->cap = u->gro ? BST_UDP_GRO_BUF : md;
	s->udp = u;
	return 0;
}

/* ---- receive: readiness path ---- */

static void rx_drop_bufs(bst_udp *u)
{
	if (u->rx != NULL)
		for (unsigned i = 0; i < BST_UDP_BATCH; i++) {
			bst_buf_unref(u->rx->buf[i]);
			u->rx->buf[i] = NULL;
		}
	for (int i = 0; i < u->npend; i++)
		bst_buf_unref(u->pend[i].buf);
	u->npend = 0;
}

static bool rx_prepare(bst_udp *u)
{
	bst_urx *x = u->rx;
	for (unsigned i = 0; i < BST_UDP_BATCH; i++) {
		if (x->buf[i] == NULL && (x->buf[i] = bst_buf_new(u->cap)) == NULL)
			return false;
		x->iov[i].iov_base = x->buf[i]->data;
		x->iov[i].iov_len = u->cap;
		struct msghdr *h = &x->mm[i].msg_hdr;
		memset(h, 0, sizeof *h);
		h->msg_name = &x->name[i];
		h->msg_namelen = sizeof x->name[i];
		h->msg_iov = &x->iov[i];
		h->msg_iovlen = 1;
		h->msg_control = x->ctl[i];
		h->msg_controllen = sizeof x->ctl[i];
		x->mm[i].msg_len = 0;
	}
	return true;
}

static void rx_end(bst_sock *s, int err)
{
	bst_udp *u = s->udp;
	u->on = false;
	bst_sock_slot_disarm_(s, &s->rslot);
	u->cb(u->cb_ud, NULL, 0, err);
}

/* Build the callback batch from the first n received messages; returns how many are
 * deliverable. A scratch buffer above BST_UDP_COPY_MAX is handed out as is. */
static int rx_collect(bst_udp *u, int n, bst_udp_msg *out)
{
	bst_urx *x = u->rx;
	int m = 0;
	for (int i = 0; i < n; i++) {
		struct msghdr *h = &x->mm[i].msg_hdr;
		size_t len = x->mm[i].msg_len;
		if ((h->msg_flags & MSG_TRUNC) != 0 || len > u->cap) {
			u->st.rx_trunc++;
			continue;
		}
		if (len == 0) {
			u->st.rx_empty++;
			continue;
		}
		bst_udp_meta meta;
		bst_udp_msg *o = &out[m];
		memset(o, 0, sizeof *o);
		if ((h->msg_flags & MSG_CTRUNC) != 0 ||
		    !bst_udp_parse_cmsg_(h->msg_control, h->msg_controllen, &meta) ||
		    !bst_udp_name_(h->msg_name, h->msg_namelen, &o->src)) {
			u->st.rx_badctl++;
			continue;
		}
		if (len <= BST_UDP_COPY_MAX) {
			bst_buf *b = bst_udp_copy_buf_(u->s->loop, len);
			if (b == NULL) {
				u->st.rx_nomem++;
				continue;
			}
			memcpy(b->data, x->buf[i]->data, len);
			b->len = len;
			o->buf = b;
		} else {
			o->buf = x->buf[i];
			o->buf->len = len;
			x->buf[i] = NULL; /* replaced before the next recvmmsg */
		}
		bst_udp_fill_msg_(o, &meta, len);
		m++;
	}
	u->st.rx_dgrams += (uint64_t)m;
	return m;
}

void bst_udp_ready_(bst_sock *s, int err)
{
	bst_udp *u = s->udp;
	if (!u->on || u->ring_rx)
		return;
	if (err != 0 && !bst_udp_transient_(err)) {
		rx_end(s, -err);
		return;
	}
	uint32_t ep = s->recv_epoch;
	unsigned total = 0;
	while (total < BST_UDP_RBUDGET) {
		if (!rx_prepare(u)) {
			rx_end(s, -ENOMEM);
			return;
		}
		unsigned vlen = BST_UDP_RBUDGET - total;
		if (vlen > BST_UDP_BATCH)
			vlen = BST_UDP_BATCH;
		int n = recvmmsg(s->fd, u->rx->mm, vlen, MSG_DONTWAIT, NULL);
		if (n < 0) {
			int e = errno;
			total++; /* an error that repeats cannot hold the loop */
			if (e == EINTR || bst_udp_transient_(e))
				continue;
			if (e == EAGAIN || e == EWOULDBLOCK)
				break;
			rx_end(s, -e);
			return;
		}
		bst_udp_msg out[BST_UDP_BATCH];
		int m = rx_collect(u, n, out);
		if (m > 0)
			u->cb(u->cb_ud, out, m, 0);
		if (s->closed || ep != s->recv_epoch || !u->on)
			return;
		total += (unsigned)n;
		if (n < (int)vlen)
			break; /* drained, most likely: arming reports whatever is left */
	}
	/* EAGAIN, drained, or the budget is spent: re-arming reports readiness that exists, so
	 * the other ready sockets run first. */
	if (bst_sock_slot_arm_(s, &s->rslot, POLLIN) != 0)
		rx_end(s, -EIO);
}

int bst_udp_start(bst_sock *s, const bst_udp_cfg *cfg, bst_udp_recv_cb cb, void *ud)
{
	if (s->closed)
		return -EBADF;
	if (cb == NULL)
		return -EINVAL;
	if (s->recv_on || s->acc_on)
		return -EBUSY;
	if (s->udp == NULL) {
		int rc = attach(s, cfg);
		if (rc != 0)
			return rc;
	}
	bst_udp *u = s->udp;
	if (u->on)
		return -EBUSY;
	u->cb = cb;
	u->cb_ud = ud;
	u->on = true;
	s->recv_epoch++;
	const bst_udp_ops *ops = s->loop->ops->udp;
	int rc = ops != NULL ? ops->recv_start(s) : -ENOSYS;
	if (rc == -ENOSYS) {
		u->ring_rx = false;
		if (u->rx == NULL && (u->rx = calloc(1, sizeof *u->rx)) == NULL)
			rc = -ENOMEM;
		else
			rc = bst_sock_slot_arm_(s, &s->rslot, POLLIN);
	} else {
		u->ring_rx = rc == 0;
	}
	if (rc != 0)
		u->on = false;
	return rc;
}

int bst_udp_stop(bst_sock *s)
{
	if (s->closed || s->udp == NULL || !s->udp->on)
		return 0;
	bst_udp *u = s->udp;
	u->on = false;
	s->recv_epoch++;
	if (u->ring_rx)
		s->loop->ops->udp->recv_stop(s);
	else
		bst_sock_slot_disarm_(s, &s->rslot);
	rx_drop_bufs(u);
	return 0;
}

/* ---- send: planning ---- */

/* Build one message: payload [off, off+len) of pk, to its destination, with the control
 * data for source selection, ECN and GSO. */
static void build_msg(bst_udp *u, bst_umsg *m, int idx, size_t off, size_t len, bool gso)
{
	const bst_udp_pkt *p = &u->pk[idx];
	memset(&m->mh, 0, sizeof m->mh);
	memset(&m->addr, 0, sizeof m->addr);
	memset(&m->ctl, 0, sizeof m->ctl);
	m->pkt = idx;
	m->off = off;
	m->len = len;
	m->gso = gso;
	m->iov.iov_base = (void *)((const unsigned char *)p->data + off);
	m->iov.iov_len = len;
	bool d4 = p->dst.ip.family == BST_IP_V4;
	if (u->family == AF_INET) {
		struct sockaddr_in *a = (void *)&m->addr;
		a->sin_family = AF_INET;
		a->sin_port = htons(p->dst.port);
		memcpy(&a->sin_addr, p->dst.ip.b, 4);
		m->mh.msg_namelen = sizeof *a;
	} else {
		struct sockaddr_in6 *a = (void *)&m->addr;
		a->sin6_family = AF_INET6;
		a->sin6_port = htons(p->dst.port);
		if (d4) { /* v4-mapped: ::ffff:a.b.c.d */
			a->sin6_addr.s6_addr[10] = 0xff;
			a->sin6_addr.s6_addr[11] = 0xff;
			memcpy(&a->sin6_addr.s6_addr[12], p->dst.ip.b, 4);
		} else {
			memcpy(&a->sin6_addr, p->dst.ip.b, 16);
		}
		m->mh.msg_namelen = sizeof *a;
	}
	m->mh.msg_name = &m->addr;
	m->mh.msg_iov = &m->iov;
	m->mh.msg_iovlen = 1;
	size_t used = 0;
#define ADD_CMSG(lvl, typ, data, n)                                                      \
	do {                                                                             \
		struct cmsghdr *cm_ = (struct cmsghdr *)(m->ctl + used);               \
		cm_->cmsg_level = (lvl);                                                 \
		cm_->cmsg_type = (typ);                                                  \
		cm_->cmsg_len = CMSG_LEN(n);                                             \
		memcpy(CMSG_DATA(cm_), (data), (n));                                     \
		used += CMSG_SPACE(n);                                                   \
	} while (0)
	if (p->src.family == BST_IP_V4) {
		struct in_pktinfo pi;
		memset(&pi, 0, sizeof pi);
		memcpy(&pi.ipi_spec_dst, p->src.b, 4);
		pi.ipi_ifindex = (int)p->src_ifindex;
		ADD_CMSG(IPPROTO_IP, IP_PKTINFO, &pi, sizeof pi);
	} else if (p->src.family == BST_IP_V6) {
		struct in6_pktinfo pi;
		memset(&pi, 0, sizeof pi);
		memcpy(&pi.ipi6_addr, p->src.b, 16);
		pi.ipi6_ifindex = p->src_ifindex;
		ADD_CMSG(IPPROTO_IPV6, IPV6_PKTINFO, &pi, sizeof pi);
	}
	if (p->ecn != 0) {
		int tos = (u->base_tos & ~3) | p->ecn;
		if (d4)
			ADD_CMSG(IPPROTO_IP, IP_TOS, &tos, sizeof tos);
		else
			ADD_CMSG(IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof tos);
	}
	if (gso) {
		uint16_t gs = p->gso_size;
		ADD_CMSG(SOL_UDP, UDP_SEGMENT, &gs, sizeof gs);
	}
#undef ADD_CMSG
	if (used != 0) {
		m->mh.msg_control = m->ctl;
		m->mh.msg_controllen = (__typeof__(m->mh.msg_controllen))used;
	}
}

int bst_udp_plan_(bst_udp *u, int max)
{
	int k = 0, pi = u->cur;
	size_t off = u->off;
	while (k < max && pi < u->npk) {
		const bst_udp_pkt *p = &u->pk[pi];
		size_t rest = p->len - off, take = rest;
		bool gso = u->gso && p->gso_size > 0 && rest > p->gso_size && off == 0;
		if (!gso && p->gso_size > 0 && rest > p->gso_size)
			take = p->gso_size;
		build_msg(u, &u->m[k], pi, off, take, gso);
		off += take;
		if (off == p->len) {
			pi++;
			off = 0;
		}
		k++;
	}
	return k;
}

void bst_udp_advance_(bst_udp *u, int n)
{
	for (int i = 0; i < n; i++) {
		const bst_umsg *m = &u->m[i];
		u->bytes += m->len;
		u->st.tx_msgs++;
		if (m->gso)
			u->st.tx_gso_msgs++;
		u->cur = m->pkt;
		u->off = m->off + m->len;
		if (u->off == u->pk[u->cur].len) {
			u->cur++;
			u->off = 0;
		}
	}
}

void bst_udp_gso_off_(bst_udp *u)
{
	if (!u->gso)
		return;
	u->gso = false;
	u->st.gso_fallbacks++;
	bst_log(BST_LOG_WARN, "udp: the kernel refused a GSO send (EIO): GSO is off for this socket");
}

/* ---- send: readiness path ---- */

static void send_complete(bst_sock *s)
{
	bst_udp *u = s->udp;
	bst_done_cb cb = u->dcb;
	void *ud = u->dud;
	size_t n = u->bytes;
	int e = u->err;
	u->send_on = false;
	u->fin = false;
	u->pk = NULL;
	bst_sock_slot_disarm_(s, &s->wslot);
	cb(ud, n, e); /* may start the next send, or close s */
}

/* Rounds of sendmmsg until the packets are out, EAGAIN, an error, or the budget. Returns 0
 * with u->fin set (ended) or POLLOUT armed (waiting), else the arm error. */
static int send_pump(bst_sock *s)
{
	bst_udp *u = s->udp;
	unsigned budget = 0;
	struct mmsghdr mmv[BST_UDP_BATCH];
	while (u->cur < u->npk) {
		if (budget >= BST_UDP_SEND_BUDGET) /* yield: other sockets get their turn */
			return bst_sock_slot_arm_(s, &s->wslot, POLLOUT);
		int max = (int)BST_UDP_BATCH;
#ifdef BST_TEST
		bst_test_udp_rounds++;
		if (bst_test_udp_eagain > 0) {
			bst_test_udp_eagain--;
			return bst_sock_slot_arm_(s, &s->wslot, POLLOUT);
		}
		if (bst_test_udp_send_limit != 0 && bst_test_udp_send_limit < (unsigned)max)
			max = (int)bst_test_udp_send_limit;
#endif
		int k = bst_udp_plan_(u, max);
		int n;
		bool fake_eio = false;
#ifdef BST_TEST
		if (bst_test_udp_gso_eio > 0)
			for (int i = 0; i < k; i++)
				if (u->m[i].gso) { /* the kernel sends what precedes it, then fails */
					if (i == 0) {
						bst_test_udp_gso_eio--;
						fake_eio = true;
					} else {
						k = i;
					}
					break;
				}
#endif
		if (fake_eio) {
			n = -1;
			errno = EIO;
		} else {
			for (int i = 0; i < k; i++)
				mmv[i] = (struct mmsghdr){.msg_hdr = u->m[i].mh};
			n = sendmmsg(s->fd, mmv, (unsigned)k, MSG_NOSIGNAL);
		}
		if (n > 0) {
			bst_udp_advance_(u, n);
			budget += (unsigned)n;
			continue;
		}
		int e = n == 0 ? EIO : errno;
		if (e == EINTR)
			continue;
		if (e == EAGAIN || e == EWOULDBLOCK || e == ENOBUFS)
			return bst_sock_slot_arm_(s, &s->wslot, POLLOUT);
		if (e == EIO && u->m[0].gso) {
			bst_udp_gso_off_(u); /* replan: the same packet as plain datagrams */
			continue;
		}
		u->err = -e;
		u->fin = true;
		return 0;
	}
	u->fin = true;
	return 0;
}

void bst_udp_send_ready_(bst_sock *s, int err)
{
	bst_udp *u = s->udp;
	if (!u->send_on)
		return;
	if (err != 0 && !bst_udp_transient_(err)) {
		u->err = -err;
		u->fin = true;
	}
	if (!u->fin && send_pump(s) != 0) {
		u->err = -EIO;
		u->fin = true;
	}
	if (u->fin)
		send_complete(s);
}

void bst_udp_slot_failed_(bst_sock *s, bool recv, int err)
{
	bst_udp *u = s->udp;
	if (recv) {
		if (u->on && !u->ring_rx) {
			u->on = false;
			u->cb(u->cb_ud, NULL, 0, err);
		}
	} else if (u->send_on) {
		u->err = err;
		u->fin = true;
		send_complete(s);
	}
}

/* ---- API ---- */

static int check_pkts(const bst_udp *u, const bst_udp_pkt *p, int n)
{
	for (int i = 0; i < n; i++) {
		const bst_udp_pkt *k = &p[i];
		if (k->data == NULL || k->len == 0 || k->len > BST_UDP_SEND_MAX_LEN || k->ecn > 3)
			return -EINVAL;
		if (k->dst.ip.family != BST_IP_V4 && k->dst.ip.family != BST_IP_V6)
			return -EINVAL;
		if (u->family == AF_INET && k->dst.ip.family != BST_IP_V4)
			return -EINVAL;
		if (k->src.family != 0 && k->src.family != k->dst.ip.family)
			return -EINVAL;
		if (k->gso_size != 0 && k->len > k->gso_size &&
		    (k->len + k->gso_size - 1) / k->gso_size > BST_UDP_GSO_SEGS)
			return -EINVAL;
	}
	return 0;
}

int bst_udp_send(bst_sock *s, const bst_udp_pkt *pkts, int n, bst_done_cb cb, void *ud)
{
	if (s->closed)
		return -EBADF;
	bst_udp *u = s->udp;
	if (cb == NULL || pkts == NULL || n <= 0 || u == NULL)
		return -EINVAL;
	if (u->send_on)
		return -EBUSY;
	int rc = check_pkts(u, pkts, n);
	if (rc != 0)
		return rc;
	u->send_on = true;
	u->fin = false;
	u->pk = pkts;
	u->npk = n;
	u->cur = 0;
	u->off = 0;
	u->bytes = 0;
	u->err = 0;
	u->dcb = cb;
	u->dud = ud;
	const bst_udp_ops *ops = s->loop->ops->udp;
	if (ops != NULL) {
		rc = ops->send_start(s);
	} else {
		/* Try now, so the datagrams leave without waiting for the loop; done still runs
		 * from the loop: an ended send arms POLLOUT, which reports at once. */
		rc = send_pump(s);
		if (rc == 0 && u->fin)
			rc = bst_sock_slot_arm_(s, &s->wslot, POLLOUT);
	}
	if (rc != 0) {
		u->send_on = false;
		u->pk = NULL;
	}
	return rc;
}

void bst_udp_stats_get(const bst_sock *s, bst_udp_stats *out)
{
	memset(out, 0, sizeof *out);
	const bst_udp *u = s->udp;
	if (u == NULL)
		return;
	*out = u->st;
	out->gso = u->gso;
	out->gro = u->gro;
	out->ring = u->ring_rx;
}

/* ---- close and free ---- */

void bst_udp_sock_close_(bst_sock *s)
{
	bst_udp *u = s->udp;
	if (u == NULL)
		return;
	u->on = false;
	u->send_on = false;
	rx_drop_bufs(u);
}

void bst_udp_free_(bst_sock *s)
{
	bst_udp *u = s->udp;
	if (u == NULL)
		return;
	rx_drop_bufs(u);
	free(u->rx);
	free(u);
	s->udp = NULL;
}

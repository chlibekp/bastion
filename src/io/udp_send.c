/* UDP send planning (header: io/udp.h): a send is the packets in order, a cursor (packet,
 * bytes sent of it), and rounds that plan up to BST_UDP_BATCH messages from the cursor
 * (bst_udp_plan_). A GSO packet is one message, whole; with GSO off the same packet is a run
 * of plain messages of gso_size. A round that sent n messages advances the cursor by exactly
 * those n (bst_udp_advance_), so a retry after EAGAIN or an EIO fallback never repeats a
 * datagram and never skips one. Both backends run these rounds (udp.c, uring_udp.c). */
#include "io/udp_priv.h"

#include "core/log.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

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


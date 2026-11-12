/* The QUIC sk_reuseport program (xdp/reuseport_quic.bpf.c), driven through a real UDP reuseport
 * group on loopback: sk_reuseport programs cannot run under BPF_PROG_TEST_RUN, so each test sends
 * crafted datagrams and asserts which socket of the group receives them. Needs CAP_BPF and
 * CAP_NET_ADMIN (the dev container is privileged); without them every test is skipped, loudly. */
#include "tap.h"

#include "http/h3/cid.h"
#include "xdp/reuseport.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NS 4

typedef struct group {
	int fd[NS];
	uint16_t port;
	bst_reuseport *r;
	int client;
} group;

static int skip_reason(void)
{
	if (geteuid() != 0) {
		printf("# SKIP: not root, cannot load BPF\n");
		return 1;
	}
	return 0;
}

static int open_group(group *g, const uint16_t *active, size_t nactive, char *why, size_t cap)
{
	memset(g, 0, sizeof *g);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	for (int i = 0; i < NS; i++) {
		g->fd[i] = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		int one = 1;
		setsockopt(g->fd[i], SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
		if (bind(g->fd[i], (struct sockaddr *)&a, sizeof a) != 0) {
			snprintf(why, cap, "bind: %s", strerror(errno));
			return -1;
		}
		if (i == 0) {
			socklen_t l = sizeof a;
			getsockname(g->fd[0], (struct sockaddr *)&a, &l);
			g->port = ntohs(a.sin_port);
		}
	}
	bst_err e = { 0 };
	bst_slot_map m = { active, nactive };
	g->r = bst_reuseport_attach(g->fd, NS, &m, &e);
	if (g->r == NULL) {
		snprintf(why, cap, "%s", e.msg);
		return -1;
	}
	g->client = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	connect(g->client, (struct sockaddr *)&a, sizeof a);
	return 0;
}

static void close_group(group *g)
{
	for (int i = 0; i < NS; i++)
		if (g->fd[i] >= 0)
			close(g->fd[i]);
	close(g->client);
	bst_reuseport_free(g->r);
}

/* Sends p and returns the index of the socket that got it, -1 for none within a second. */
static int which(group *g, const uint8_t *p, size_t n)
{
	if (send(g->client, p, n, 0) != (ssize_t)n)
		return -2;
	struct pollfd pf[NS];
	for (int i = 0; i < NS; i++)
		pf[i] = (struct pollfd){ .fd = g->fd[i], .events = POLLIN };
	if (poll(pf, NS, 1000) <= 0)
		return -1;
	for (int i = 0; i < NS; i++)
		if (pf[i].revents & POLLIN) {
			uint8_t buf[2048];
			ssize_t k = recv(g->fd[i], buf, sizeof buf, 0);
			if (k != (ssize_t)n || memcmp(buf, p, n) != 0)
				return -3;
			return i;
		}
	return -1;
}

static size_t short_hdr(uint8_t *p, uint16_t slot)
{
	p[0] = 0x40;
	bst_cid_generate(slot, p + 1, BST_CID_LEN);
	memset(p + 1 + BST_CID_LEN, 0xaa, 40);
	return 1 + BST_CID_LEN + 40;
}

static size_t long_hdr(uint8_t *p, const uint8_t *dcid, size_t dlen)
{
	size_t n = 0;
	p[n++] = 0xc0; /* Initial */
	p[n++] = 0, p[n++] = 0, p[n++] = 0, p[n++] = 1;
	p[n++] = (uint8_t)dlen;
	memcpy(p + n, dcid, dlen);
	n += dlen;
	p[n++] = 8;
	memset(p + n, 0x11, 8);
	n += 8;
	memset(p + n, 0, 1200 - n); /* padded like a real Initial */
	return 1200;
}

#define GROUP_OR_SKIP(g, act, nact)                                                             \
	do {                                                                                    \
		if (skip_reason())                                                              \
			return;                                                                 \
		char why_[512];                                                                 \
		if (open_group(&(g), (act), (nact), why_, sizeof why_) != 0)                    \
			TAP_FAIL_("reuseport group: %s", why_);                                 \
	} while (0)

/* A short header reaches the socket of the slot in its connection ID, for every slot. */
TEST(bpf_short_header)
{
	group g;
	uint16_t act[] = { 0, 1, 2, 3 };
	GROUP_OR_SKIP(g, act, 4);
	uint8_t p[1300];
	for (int round = 0; round < 8; round++)
		for (uint16_t s = 0; s < NS; s++) {
			size_t n = short_hdr(p, s);
			int got = which(&g, p, n);
			if (got != s) {
				close_group(&g);
				TAP_FAIL_("slot %u went to %d", s, got);
			}
		}
	uint64_t st[3];
	bst_reuseport_stats(g.r, st);
	ASSERT(st[0] >= 32);
	/* A long header with a DCID of Bastion's length (Handshake, 0-RTT, an Initial after Retry) too. */
	uint8_t cid[BST_CID_LEN];
	bst_cid_generate(2, cid, sizeof cid);
	ASSERT_EQ(which(&g, p, long_hdr(p, cid, sizeof cid)), 2);
	close_group(&g);
}

/* A long-header Initial with a client-chosen DCID reaches an active slot, and every datagram of
 * the same 4-tuple reaches the same one. */
TEST(bpf_initial_hash)
{
	group g;
	uint16_t act[] = { 1, 2 };
	GROUP_OR_SKIP(g, act, 2);
	uint8_t p[1300], dcid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	size_t n = long_hdr(p, dcid, sizeof dcid);
	int first = which(&g, p, n);
	if (first != 1 && first != 2) {
		close_group(&g);
		TAP_FAIL_("Initial went to %d", first);
	}
	for (int i = 0; i < 10; i++) {
		dcid[0] = (uint8_t)i;
		long_hdr(p, dcid, sizeof dcid);
		int got = which(&g, p, n);
		if (got != first) {
			close_group(&g);
			TAP_FAIL_("same 4-tuple went to %d then %d", first, got);
		}
	}
	uint64_t st[3];
	bst_reuseport_stats(g.r, st);
	ASSERT_EQ(st[1], 11);
	close_group(&g);
}

/* A slot out of range, or one whose socket is gone, falls back to the active generation's hash:
 * never a drop. */
TEST(bpf_invalid_slot)
{
	group g;
	uint16_t act[] = { 2 };
	GROUP_OR_SKIP(g, act, 1);
	uint8_t p[256];
	size_t n = short_hdr(p, 999); /* no such slot */
	ASSERT_EQ(which(&g, p, n), 2);
	n = short_hdr(p, BST_CID_NO_SLOT - 1);
	ASSERT_EQ(which(&g, p, n), 2);
	close(g.fd[3]); /* the kernel removes it from the socket map */
	g.fd[3] = -1;
	n = short_hdr(p, 3);
	ASSERT_EQ(which(&g, p, n), 2);
	/* the active set can change while the group runs */
	uint16_t act2[] = { 0 };
	bst_slot_map m = { act2, 1 };
	bst_err e = { 0 };
	ASSERT_EQ(bst_reuseport_set_active(g.r, &m, &e), 0);
	ASSERT_EQ(which(&g, p, n), 0);
	uint16_t bad[] = { 7 };
	m = (bst_slot_map){ bad, 1 };
	ASSERT_EQ(bst_reuseport_set_active(g.r, &m, &e), -1);
	ASSERT_EQ(which(&g, p, n), 0);
	close_group(&g);
}

/* A 1-byte datagram, and a long header too short to hold its DCID, are delivered safely. */
TEST(bpf_truncated)
{
	group g;
	uint16_t act[] = { 3 };
	GROUP_OR_SKIP(g, act, 1);
	uint8_t one = 0x40;
	ASSERT_EQ(which(&g, &one, 1), 3);
	uint8_t lh[7] = { 0xc0, 0, 0, 0, 1, BST_CID_LEN, 9 };
	ASSERT_EQ(which(&g, lh, sizeof lh), 3);
	uint8_t sh[4] = { 0x40, 1, 2, 3 };
	ASSERT_EQ(which(&g, sh, sizeof sh), 3);
	close_group(&g);
}

TAP_MAIN()

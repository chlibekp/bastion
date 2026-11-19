/* See channel.h. */
#include "proc/channel.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define MAGIC0 0xB5
#define MAGIC1 0x7A

/* The exact payload length of a type, or -1 for an unknown type. */
static int payload_len(unsigned type)
{
	switch (type) {
	case BST_MSG_READY:
	case BST_MSG_STOP:
	case BST_MSG_LOG_REOPEN:
		return 1;
	default:
		return -1;
	}
}

size_t bst_chan_encode(const bst_msg *m, void *buf, size_t cap)
{
	unsigned char *p = buf;
	int plen = payload_len((unsigned)m->type);
	if (plen < 0 || cap < BST_CHAN_HDR + (size_t)plen)
		return 0;
	p[0] = MAGIC0;
	p[1] = MAGIC1;
	p[2] = (unsigned char)m->type;
	p[3] = (unsigned char)plen;
	p[BST_CHAN_HDR] = m->type == BST_MSG_READY	? (unsigned char)m->ready.backend
			  : m->type == BST_MSG_LOG_REOPEN ? m->log_reopen.file
							  : (unsigned char)m->stop.graceful;
	return BST_CHAN_HDR + (size_t)plen;
}

bool bst_chan_decode(const void *buf, size_t len, bst_msg *out)
{
	const unsigned char *p = buf;
	if (len < BST_CHAN_HDR || p[0] != MAGIC0 || p[1] != MAGIC1)
		return false;
	int plen = payload_len(p[2]);
	if (plen < 0 || p[3] != plen || len != BST_CHAN_HDR + (size_t)plen)
		return false;
	unsigned char v = p[BST_CHAN_HDR];
	memset(out, 0, sizeof *out);
	out->type = (bst_msg_type)p[2];
	if (out->type == BST_MSG_READY) {
		if (v != BST_BACKEND_URING && v != BST_BACKEND_EPOLL)
			return false;
		out->ready.backend = (bst_backend)v;
	} else if (out->type == BST_MSG_LOG_REOPEN) {
		out->log_reopen.file = v;
	} else {
		if (v > 1)
			return false;
		out->stop.graceful = v == 1;
	}
	return true;
}

int bst_chan_pair(int sv[2])
{
	return socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv);
}

int bst_chan_send(int fd, const bst_msg *m)
{
	unsigned char buf[BST_CHAN_MAX];
	size_t n = bst_chan_encode(m, buf, sizeof buf);
	if (n == 0)
		return -EINVAL;
	ssize_t w;
	do
		w = send(fd, buf, n, MSG_DONTWAIT | MSG_NOSIGNAL);
	while (w < 0 && errno == EINTR);
	return w < 0 ? -errno : 0;
}

int bst_chan_recv(int fd, bst_msg *out)
{
	unsigned char buf[BST_CHAN_MAX];
	ssize_t r;
	/* MSG_TRUNC returns the real length, so a long datagram cannot pass as its first bytes. */
	do
		r = recv(fd, buf, sizeof buf, MSG_DONTWAIT | MSG_TRUNC);
	while (r < 0 && errno == EINTR);
	if (r == 0)
		return 0; /* a SEQPACKET peer's close: zero-length sends are not ours */
	if (r < 0 && errno == ECONNRESET)
		return 0; /* the peer closed with our message unread: still the peer gone */
	if (r < 0)
		return errno == EWOULDBLOCK ? -EAGAIN : -errno;
	if ((size_t)r > sizeof buf || !bst_chan_decode(buf, (size_t)r, out))
		return -EPROTO;
	return 1;
}

int bst_chan_send_fd(int fd, const bst_msg *m, int pass)
{
	unsigned char buf[BST_CHAN_MAX];
	size_t n = bst_chan_encode(m, buf, sizeof buf);
	if (n == 0 || pass < 0)
		return -EINVAL;
	union {
		char b[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} ctl;
	memset(&ctl, 0, sizeof ctl);
	struct iovec iov = { .iov_base = buf, .iov_len = n };
	struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctl.b,
			     .msg_controllen = sizeof ctl.b };
	struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &pass, sizeof pass);
	ssize_t w;
	do
		w = sendmsg(fd, &mh, MSG_DONTWAIT | MSG_NOSIGNAL);
	while (w < 0 && errno == EINTR);
	return w < 0 ? -errno : 0;
}

int bst_chan_recv_fd(int fd, bst_msg *out, int *passed)
{
	unsigned char buf[BST_CHAN_MAX];
	union {
		char b[CMSG_SPACE(4 * sizeof(int))];
		struct cmsghdr align;
	} ctl;
	*passed = -1;
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof buf };
	struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctl.b,
			     .msg_controllen = sizeof ctl.b };
	ssize_t r;
	do
		r = recvmsg(fd, &mh, MSG_DONTWAIT | MSG_TRUNC | MSG_CMSG_CLOEXEC);
	while (r < 0 && errno == EINTR);
	if (r < 0 && errno == ECONNRESET)
		return 0;
	if (r < 0)
		return errno == EWOULDBLOCK ? -EAGAIN : -errno;
	/* every descriptor that came is closed unless it is the one a valid message carries */
	int got = -1;
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm != NULL; cm = CMSG_NXTHDR(&mh, cm)) {
		if (cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS)
			continue;
		size_t k = (cm->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		for (size_t i = 0; i < k; i++) {
			int x;
			memcpy(&x, CMSG_DATA(cm) + i * sizeof(int), sizeof x);
			if (got < 0)
				got = x;
			else
				close(x);
		}
	}
	if (r == 0) {
		if (got >= 0)
			close(got);
		return 0;
	}
	if ((size_t)r > sizeof buf || (mh.msg_flags & MSG_CTRUNC) || !bst_chan_decode(buf, (size_t)r, out)) {
		if (got >= 0)
			close(got);
		return -EPROTO;
	}
	*passed = got;
	return 1;
}

/* Stream I/O over the readiness slots (architecture section 3): accept, recv, send with
 * file segments, connect. Non-blocking syscalls driven by readiness, so it serves the
 * epoll backend; the io_uring backend (Task 3) will provide completion-based versions of
 * the same API. Nothing here blocks the loop thread: file pages are probed with
 * preadv2(RWF_NOWAIT) and cold ones are read ahead on the aio pool before sendfile. */
#include "io/net.h"

#include "core/log.h"
#include "io/loop_priv.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef RWF_NOWAIT
#define RWF_NOWAIT 0x00000008
#endif

#define RA_RETRY_MS 2u /* pool queue full: retry the readahead submit after this */

/* ---- recv buffers ---- */

typedef struct {
	bst_buf b; /* first: the slab object is the header */
	unsigned char data[BST_RECV_BUF_SIZE];
} rbuf;

static void rbuf_release(bst_buf *b, void *ctx)
{
	bst_loop *l = ctx;
	bst_slab_put(l->rbufs, b);
}

static bst_buf *rbuf_get(bst_loop *l)
{
	rbuf *r = bst_slab_get(l->rbufs);
	if (r == NULL)
		return NULL;
	bst_buf_init(&r->b, r->data, sizeof r->data, rbuf_release, l);
	return &r->b;
}

void bst_net_loop_free_(bst_loop *l)
{
	if (l->rbufs != NULL)
		bst_slab_free(l->rbufs);
	l->rbufs = NULL;
}

/* ---- close hook ---- */

void bst_net_sock_close_(bst_sock *s)
{
	if (s->ra_timer.pprev != NULL) {
		bst_timer_cancel(&s->ra_timer);
		s->ra_busy = false;
		bst_sock_release_(s);
	}
	bst_loop *l = s->loop;
	for (bst_sock **pp = &l->listeners; *pp != NULL; pp = &(*pp)->lnext)
		if (*pp == s) {
			*pp = s->lnext;
			break;
		}
}

/* ---- accept ---- */

static void to_peer(const struct sockaddr_storage *ss, bst_sockaddr *out, bool *ok)
{
	*ok = true;
	memset(out, 0, sizeof *out);
	if (ss->ss_family == AF_INET) {
		const struct sockaddr_in *a = (const void *)ss;
		out->ip.family = BST_IP_V4;
		memcpy(out->ip.b, &a->sin_addr, 4);
		out->port = ntohs(a->sin_port);
	} else if (ss->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const void *)ss;
		out->ip.family = BST_IP_V6;
		memcpy(out->ip.b, &a->sin6_addr, 16);
		out->port = ntohs(a->sin6_port);
	} else {
		*ok = false;
	}
}

static void accept_ready(bst_sock *s)
{
	if (!s->acc_on)
		return;
	uint32_t ep = s->recv_epoch;
	for (unsigned i = 0; i < BST_ACCEPT_BUDGET; i++) {
		struct sockaddr_storage ss;
		socklen_t sl = sizeof ss;
		int fd = accept4(s->fd, (struct sockaddr *)&ss, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd >= 0) {
			bst_sockaddr peer;
			bool ok;
			to_peer(&ss, &peer, &ok);
			s->acc_cb(s->acc_ud, fd, ok ? &peer : NULL, 0);
			if (s->closed || ep != s->recv_epoch || !s->acc_on)
				return;
			continue;
		}
		int e = errno;
		if (e == EINTR || e == ECONNABORTED || e == EPROTO)
			continue;
		if (e == EAGAIN || e == EWOULDBLOCK) {
			if (bst_sock_slot_arm_(s, &s->rslot, POLLIN) != 0)
				goto fail;
			return;
		}
		/* EMFILE, ENFILE, ENOBUFS, ENOMEM...: report and pause, never spin. */
		s->acc_on = false;
		s->acc_paused = true;
		s->acc_cb(s->acc_ud, -1, NULL, -e);
		return;
	}
	if (bst_sock_slot_arm_(s, &s->rslot, POLLIN) == 0) /* budget spent: yield */
		return;
fail:
	s->acc_on = false;
	s->acc_paused = true;
	s->acc_cb(s->acc_ud, -1, NULL, -EIO);
}

int bst_io_accept_start(bst_loop *l, int listen_fd, bst_accept_cb cb, void *ud)
{
	if (cb == NULL)
		return -EINVAL;
	bst_sock *s;
	for (s = l->listeners; s != NULL; s = s->lnext)
		if (s->fd == listen_fd)
			break;
	if (s != NULL) {
		if (!s->acc_paused)
			return -EEXIST;
	} else {
		if (fcntl(listen_fd, F_GETFL) < 0)
			return -errno;
		s = bst_sock_wrap(l, listen_fd);
		if (s == NULL)
			return -ENOMEM;
		s->borrowed = true;
		s->lnext = l->listeners;
		l->listeners = s;
	}
	s->acc_cb = cb;
	s->acc_ud = ud;
	s->acc_paused = false;
	s->acc_on = true;
	s->recv_epoch++;
	int rc = bst_sock_slot_arm_(s, &s->rslot, POLLIN);
	if (rc != 0) {
		s->acc_on = false;
		s->acc_paused = true;
	}
	return rc;
}

int bst_io_accept_stop(bst_loop *l, int listen_fd)
{
	for (bst_sock *s = l->listeners; s != NULL; s = s->lnext)
		if (s->fd == listen_fd) {
			bst_sock_close(s); /* borrowed: the fd stays open */
			return 0;
		}
	return -ENOENT;
}

/* ---- recv ---- */

static void recv_end(bst_sock *s, int err)
{
	s->recv_on = false;
	bst_sock_slot_disarm_(s, &s->rslot);
	s->recv_cb(s->recv_ud, NULL, err);
}

void bst_net_recv_ready_(bst_sock *s, uint32_t events, int err)
{
	(void)events;
	if (s->acc_on) {
		accept_ready(s);
		return;
	}
	if (!s->recv_on)
		return;
	if (err != 0) { /* SO_ERROR was consumed by the core: the read would just say EOF */
		recv_end(s, -err);
		return;
	}
	uint32_t ep = s->recv_epoch;
	for (unsigned i = 0; i < BST_RECV_BUDGET; i++) {
		bst_buf *b = rbuf_get(s->loop);
		if (b == NULL) {
			recv_end(s, -ENOMEM);
			return;
		}
		ssize_t n = recv(s->fd, b->data, b->cap, 0);
		if (n > 0) {
			b->len = (size_t)n;
			s->recv_cb(s->recv_ud, b, 0); /* the callback owns the reference */
			if (s->closed || ep != s->recv_epoch || !s->recv_on)
				return;
			continue;
		}
		int e = errno;
		bst_buf_unref(b);
		if (n == 0) {
			recv_end(s, 0);
			return;
		}
		if (e == EINTR)
			continue;
		if (e == EAGAIN || e == EWOULDBLOCK) {
			if (bst_sock_slot_arm_(s, &s->rslot, POLLIN) != 0)
				recv_end(s, -EIO);
			return;
		}
		recv_end(s, -e);
		return;
	}
	/* Budget spent with data possibly left: re-arming reports it at the next wait, after
	 * every other ready socket had its turn. */
	if (bst_sock_slot_arm_(s, &s->rslot, POLLIN) != 0)
		recv_end(s, -EIO);
}

int bst_io_recv_start(bst_sock *s, bst_recv_cb cb, void *ud)
{
	if (s->closed)
		return -EBADF;
	if (cb == NULL)
		return -EINVAL;
	if (s->recv_on || s->acc_on)
		return -EBUSY;
	if (s->loop->rbufs == NULL) {
		s->loop->rbufs = bst_slab_new(sizeof(rbuf), 32);
		if (s->loop->rbufs == NULL)
			return -ENOMEM;
	}
	s->recv_cb = cb;
	s->recv_ud = ud;
	s->recv_on = true;
	s->recv_epoch++;
	int rc = bst_sock_slot_arm_(s, &s->rslot, POLLIN);
	if (rc != 0)
		s->recv_on = false;
	return rc;
}

int bst_io_recv_stop(bst_sock *s)
{
	s->recv_on = false;
	s->recv_epoch++;
	bst_sock_slot_disarm_(s, &s->rslot);
	return 0;
}

/* ---- send ---- */

static void send_finish(bst_sock *s, int err)
{
	bst_done_cb cb = s->send_cb;
	void *ud = s->send_ud;
	size_t n = s->send_bytes;
	s->send_on = false;
	s->is_connect = false;
	s->send_chain = NULL;
	bst_sock_slot_disarm_(s, &s->wslot);
	cb(ud, n, err); /* may start the next send, or close s */
}

static int send_err(const bst_sock *s, int e)
{
	return e == EPIPE && s->last_err != 0 ? -s->last_err : -e;
}

/* Cold pages: true when every probed page is cached. A filesystem that cannot do
 * RWF_NOWAIT is skipped for that fd and logged once. */
static bool resident(bst_sock *s, int fd, off_t off, size_t len)
{
	static atomic_flag logged = ATOMIC_FLAG_INIT;
	if (s->nowait_fd == fd)
		return true;
	for (size_t p = 0;; p += BST_PROBE_STRIDE) {
		size_t at = p < len ? p : len - 1;
		char c;
		struct iovec v = {.iov_base = &c, .iov_len = 1};
		ssize_t r = preadv2(fd, &v, 1, off + (off_t)at, RWF_NOWAIT);
		if (r < 0) {
			int e = errno;
			if (e == EAGAIN)
				return false;
			if (e == EOPNOTSUPP || e == ENOSYS || e == EINVAL) {
				s->nowait_fd = fd;
				if (!atomic_flag_test_and_set(&logged))
					bst_log(BST_LOG_INFO, "preadv2(RWF_NOWAIT) unsupported here "
						"(%s); skipping residency probes for such files",
						strerror(e));
			}
			return true; /* sendfile reports a real error */
		}
		if (r == 0 || at == len - 1)
			return true; /* r == 0: past EOF, sendfile will say so */
	}
}

static void send_pump(bst_sock *s);

static void ra_work(void *p)
{
	bst_sock *s = p;
	(void)readahead(s->ra.fd, s->ra.off, s->ra.len);
	/* readahead only starts the I/O: wait here, on the pool, until the probed pages are
	 * in, so the loop's sendfile finds them cached. */
	for (size_t at = 0;; at += BST_PROBE_STRIDE) {
		size_t pos = at < s->ra.len ? at : s->ra.len - 1;
		char c;
		if (pread(s->ra.fd, &c, 1, s->ra.off + (off_t)pos) <= 0 || pos == s->ra.len - 1)
			break;
	}
}

static void ra_resume(bst_sock *s, bool skip)
{
	bst_sock_release_(s);
	s->ra_busy = false;
	if (s->closed || !s->send_on)
		return;
	s->ra_skip = skip;
	send_pump(s);
}

static void ra_done(void *p)
{
	ra_resume(p, true);
}

static void ra_retry(void *p)
{
	ra_resume(p, false);
}

static void start_readahead(bst_sock *s, int fd, off_t off, size_t len)
{
	s->ra.fd = fd;
	s->ra.off = off;
	s->ra.len = len;
	s->inflight++;
	s->ra_busy = true;
	int rc = bst_aio_submit(s->loop, ra_work, ra_done, s);
	if (rc == 0)
		return;
	if (rc == -EAGAIN) { /* pool saturated: try again shortly, never block the loop */
		bst_loop_timer_arm(s->loop, &s->ra_timer, RA_RETRY_MS, ra_retry, s);
		return;
	}
	/* Pool gone (shutdown): send anyway. */
	ra_resume(s, true);
}

static ssize_t do_sendfile(bst_sock *s, int fd, off_t off, size_t len)
{
	/* sendfile has no MSG_NOSIGNAL and may raise SIGPIPE: block it for the call and
	 * swallow what it queued. */
	sigset_t m, old;
	sigemptyset(&m);
	sigaddset(&m, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &m, &old);
	off_t o = off;
	ssize_t n = sendfile(s->fd, fd, &o, len);
	int e = errno;
	if (n < 0 && e == EPIPE) {
		struct timespec z = {0, 0};
		while (sigtimedwait(&m, NULL, &z) < 0 && errno == EINTR) {
		}
	}
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	errno = e;
	return n;
}

static void send_pump(bst_sock *s)
{
	bst_chain *c = s->send_chain;
	size_t budget = BST_SEND_BUDGET;
	while (bst_chain_len(c) > 0) {
		if (budget == 0) { /* yield: re-arming reports writability at the next wait */
			if (bst_sock_slot_arm_(s, &s->wslot, POLLOUT) != 0)
				send_finish(s, -EIO);
			return;
		}
		int fd;
		off_t off, flen;
		ssize_t n;
		bool is_file = bst_chain_front_file(c, &fd, &off, &flen) != 0;
		if (is_file) {
			size_t chunk = (uint64_t)flen > BST_SEND_CHUNK ? BST_SEND_CHUNK : (size_t)flen;
			if (s->ra_skip)
				s->ra_skip = false;
			else if (!resident(s, fd, off, chunk)) {
				start_readahead(s, fd, off, chunk);
				return;
			}
			n = do_sendfile(s, fd, off, chunk);
		} else {
			struct iovec iov[IOV_MAX];
			int cnt = bst_chain_to_iov(c, iov, IOV_MAX);
			struct msghdr mh = {.msg_iov = iov, .msg_iovlen = (size_t)cnt};
			n = sendmsg(s->fd, &mh, MSG_NOSIGNAL);
		}
		if (n > 0) {
			bst_chain_consume(c, (uint64_t)n);
			s->send_bytes += (size_t)n;
			budget = budget > (size_t)n ? budget - (size_t)n : 0;
			continue;
		}
		if (n == 0) { /* file ended before its segment did (truncated under us) */
			send_finish(s, -EIO);
			return;
		}
		int e = errno;
		if (e == EINTR)
			continue;
		if (e == EAGAIN || e == EWOULDBLOCK) {
			if (bst_sock_slot_arm_(s, &s->wslot, POLLOUT) != 0)
				send_finish(s, -EIO);
			return;
		}
		send_finish(s, send_err(s, e));
		return;
	}
	send_finish(s, 0);
}

static void connect_ready(bst_sock *s, uint32_t events, int err)
{
	int e = s->conn_err != 0 ? s->conn_err : err;
	s->conn_err = 0;
	if (e == 0) {
		socklen_t len = sizeof e;
		if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &e, &len) != 0)
			e = errno;
	}
	if (e == 0 && !(events & POLLOUT)) { /* not connected yet */
		if (bst_sock_slot_arm_(s, &s->wslot, POLLOUT) != 0)
			send_finish(s, -EIO);
		return;
	}
	send_finish(s, e != 0 ? -e : 0);
}

void bst_net_send_ready_(bst_sock *s, uint32_t events, int err)
{
	if (!s->send_on)
		return;
	if (s->is_connect) {
		connect_ready(s, events, err);
		return;
	}
	if (err != 0) {
		send_finish(s, -err);
		return;
	}
	send_pump(s);
}

static int send_begin(bst_sock *s, bst_chain *c, bst_done_cb cb, void *ud, bool is_connect)
{
	if (s->closed)
		return -EBADF;
	if (cb == NULL)
		return -EINVAL;
	if (s->send_on)
		return -EBUSY;
	s->send_on = true;
	s->is_connect = is_connect;
	s->send_chain = c;
	s->send_cb = cb;
	s->send_ud = ud;
	s->send_bytes = 0;
	s->ra_skip = false;
	/* Always completes from the loop: arming reports writability that already exists. */
	int rc = bst_sock_slot_arm_(s, &s->wslot, POLLOUT);
	if (rc != 0) {
		s->send_on = false;
		s->is_connect = false;
	}
	return rc;
}

int bst_io_send(bst_sock *s, bst_chain *c, bst_done_cb cb, void *ud)
{
	if (c == NULL)
		return -EINVAL;
	return send_begin(s, c, cb, ud, false);
}

int bst_io_connect(bst_sock *s, const bst_sockaddr *to, bst_done_cb cb, void *ud)
{
	if (to == NULL)
		return -EINVAL;
	struct sockaddr_storage ss;
	socklen_t sl;
	memset(&ss, 0, sizeof ss);
	if (to->ip.family == BST_IP_V4) {
		struct sockaddr_in *a = (void *)&ss;
		a->sin_family = AF_INET;
		a->sin_port = htons(to->port);
		memcpy(&a->sin_addr, to->ip.b, 4);
		sl = sizeof *a;
	} else if (to->ip.family == BST_IP_V6) {
		struct sockaddr_in6 *a = (void *)&ss;
		a->sin6_family = AF_INET6;
		a->sin6_port = htons(to->port);
		memcpy(&a->sin6_addr, to->ip.b, 16);
		sl = sizeof *a;
	} else {
		return -EINVAL;
	}
	int rc = send_begin(s, NULL, cb, ud, true);
	if (rc != 0)
		return rc;
	if (connect(s->fd, (struct sockaddr *)&ss, sl) != 0 && errno != EINPROGRESS &&
	    errno != EINTR)
		s->conn_err = errno; /* reported through the callback like any other result */
	return 0;
}

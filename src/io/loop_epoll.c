/* epoll backend. The only file under src/ that may use epoll_*.
 *
 * Sockets are registered EPOLLET|EPOLLONESHOT: bst_io_poll is one-shot, so after an event
 * the kernel disarms the fd and re-arming is EPOLL_CTL_MOD, which re-checks readiness and
 * reports anything already pending (no edge is lost between callback and re-arm). */
#include "core/log.h"
#include "io/loop_priv.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#define EP_BATCH 256

typedef struct {
	int ep;
	int efd; /* wake eventfd; its epoll data.ptr is NULL */
	struct epoll_event ev[EP_BATCH];
} ep_state;

static int ep_open(bst_loop *l, const bst_loop_cfg *cfg, bst_err *err)
{
	(void)cfg;
	ep_state *st = calloc(1, sizeof *st);
	if (st == NULL) {
		bst_err_set(err, "out of memory");
		return -1;
	}
	st->ep = epoll_create1(EPOLL_CLOEXEC);
	if (st->ep < 0) {
		bst_err_set(err, "epoll_create1: %s", strerror(errno));
		free(st);
		return -1;
	}
	st->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (st->efd < 0) {
		bst_err_set(err, "eventfd: %s", strerror(errno));
		close(st->ep);
		free(st);
		return -1;
	}
	struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.ptr = NULL};
	if (epoll_ctl(st->ep, EPOLL_CTL_ADD, st->efd, &ev) != 0) {
		bst_err_set(err, "epoll_ctl(eventfd): %s", strerror(errno));
		close(st->efd);
		close(st->ep);
		free(st);
		return -1;
	}
	l->be = st;
	return 0;
}

static void ep_close(bst_loop *l)
{
	ep_state *st = l->be;
	close(st->efd);
	close(st->ep);
	free(st);
	l->be = NULL;
}

static int ep_wait(bst_loop *l, int timeout_ms)
{
	ep_state *st = l->be;
	int n = epoll_wait(st->ep, st->ev, EP_BATCH, timeout_ms);
	if (n < 0)
		return errno == EINTR ? 0 : -errno;
	return n;
}

static uint32_t from_epoll(uint32_t e)
{
	uint32_t p = 0;
	if (e & EPOLLIN)
		p |= POLLIN;
	if (e & EPOLLOUT)
		p |= POLLOUT;
	if (e & EPOLLRDHUP)
		p |= POLLRDHUP;
	if (e & EPOLLERR)
		p |= POLLERR;
	if (e & EPOLLHUP)
		p |= POLLHUP;
	return p;
}

static uint32_t to_epoll(uint32_t p)
{
	uint32_t e = 0;
	if (p & POLLIN)
		e |= EPOLLIN;
	if (p & POLLOUT)
		e |= EPOLLOUT;
	if (p & POLLRDHUP)
		e |= EPOLLRDHUP;
	return e;
}

static void ep_dispatch(bst_loop *l, int n)
{
	ep_state *st = l->be;
	for (int i = 0; i < n; i++) {
		bst_sock *s = st->ev[i].data.ptr;
		if (s == NULL) {
			uint64_t v;
			ssize_t r;
			do {
				r = read(st->efd, &v, sizeof v);
			} while (r < 0 && errno == EINTR);
			bst_loop_woken_(l);
			continue;
		}
		/* s may have been closed by an earlier callback in this batch; its memory stays
		 * valid until the iteration ends and bst_sock_ready_ skips it. */
		bst_sock_ready_(s, from_epoll(st->ev[i].events));
	}
}

static int ep_poll_arm(bst_sock *s, uint32_t events)
{
	ep_state *st = s->loop->be;
	struct epoll_event ev = {.events = to_epoll(events) | EPOLLET | EPOLLONESHOT,
				 .data.ptr = s};
	int op = s->registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
	if (epoll_ctl(st->ep, op, s->fd, &ev) != 0)
		return -errno;
	s->registered = true;
	return 0;
}

static void ep_sock_detach(bst_sock *s)
{
	if (!s->registered)
		return;
	ep_state *st = s->loop->be;
	(void)epoll_ctl(st->ep, EPOLL_CTL_DEL, s->fd, NULL);
	s->registered = false;
}

static void ep_wake(bst_loop *l)
{
	ep_state *st = l->be;
	int saved = errno;
	uint64_t one = 1;
	/* EAGAIN means the counter is already saturated, so a wake is pending anyway. */
	ssize_t r = write(st->efd, &one, sizeof one);
	(void)r;
	errno = saved;
}

const bst_loop_ops bst_loop_epoll_ops = {
	.id = BST_BACKEND_EPOLL,
	.open = ep_open,
	.close = ep_close,
	.wait = ep_wait,
	.dispatch = ep_dispatch,
	.poll_arm = ep_poll_arm,
	.sock_detach = ep_sock_detach,
	.wake = ep_wake,
};

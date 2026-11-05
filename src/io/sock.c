#include "io/sock.h"

#include "io/loop_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

bst_sock *bst_sock_wrap(bst_loop *l, int fd)
{
	int fl = fcntl(fd, F_GETFL);
	if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0)
		return NULL;
	bst_sock *s = bst_slab_get(l->socks);
	if (s == NULL)
		return NULL;
	*s = (bst_sock){.loop = l, .fd = fd, .nowait_fd = -1};
	bst_timer_init(&s->ra_timer);
	return s;
}

void bst_sock_close(bst_sock *s)
{
	if (s == NULL || s->closed)
		return;
	bst_loop *l = s->loop;
	s->closed = true;
	s->armed = false;
	s->rslot.armed = false;
	s->wslot.armed = false;
	s->recv_on = s->send_on = s->acc_on = false;
	bst_net_sock_close_(s);
	l->ops->sock_detach(s);
	if (!s->borrowed)
		close(s->fd);
	s->fd = -1;
	/* Freed at the end of the iteration: the current batch may still point at s. */
	s->dnext = l->dead;
	l->dead = s;
}

static uint32_t union_want(const bst_sock *s)
{
	return (s->armed ? s->want : 0) | (s->rslot.armed ? s->rslot.want : 0) |
	       (s->wslot.armed ? s->wslot.want : 0);
}

/* Program the backend with the union of armed slots. force: also when unchanged (an
 * arm, or a one-shot that fired, needs the re-check of existing readiness). */
static int sync_kernel(bst_sock *s, bool force)
{
	uint32_t u = union_want(s);
	if (u == 0)
		return 0;
	if (!force && u == s->kmask && !s->kdisarmed)
		return 0;
	int rc = s->loop->ops->poll_arm(s, u);
	if (rc == 0) {
		s->kmask = u;
		s->kdisarmed = false;
	}
	return rc;
}

int bst_sock_slot_arm_(bst_sock *s, bst_slot *slot, uint32_t events)
{
	if (s->closed)
		return -EBADF;
	bst_slot old = *slot;
	slot->want = events;
	slot->armed = true;
	int rc = sync_kernel(s, true);
	if (rc != 0)
		*slot = old;
	return rc;
}

void bst_sock_slot_disarm_(bst_sock *s, bst_slot *slot)
{
	if (!slot->armed)
		return;
	slot->armed = false;
	if (!s->closed)
		(void)sync_kernel(s, false);
}

int bst_io_poll(bst_sock *s, uint32_t events, bst_poll_cb cb, void *ud)
{
	if (s->closed)
		return -EBADF;
	bst_slot slot = {.want = events, .armed = true};
	bool was = s->armed;
	uint32_t was_want = s->want;
	s->want = slot.want;
	s->armed = true;
	int rc = sync_kernel(s, true);
	if (rc != 0) {
		s->armed = was;
		s->want = was_want;
		return rc;
	}
	s->cb = cb;
	s->ud = ud;
	s->gen++; /* a backend with async completions tags operations with this */
	return 0;
}

void bst_sock_ready_(bst_sock *s, uint32_t events)
{
	if (s->closed)
		return;
	/* An event fetched before a slot was replaced may not match what is wanted now. Drop
	 * it without disarming, so the replacement's own event still arrives. */
	const uint32_t always = POLLERR | POLLHUP;
	bool m_poll = s->armed && (events & (s->want | always));
	bool m_recv = s->rslot.armed && (events & (s->rslot.want | always));
	bool m_send = s->wslot.armed && (events & (s->wslot.want | always));
	if (!m_poll && !m_recv && !m_send)
		return;
	s->kdisarmed = true; /* the one-shot registration was consumed */
	int err = 0;
	if (events & POLLERR) {
		socklen_t len = sizeof err;
		if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0)
			err = 0;
		if (err != 0)
			s->last_err = err;
	}
	/* Each slot is re-checked: an earlier callback may have closed or re-armed. */
	if (m_recv && s->rslot.armed) {
		s->rslot.armed = false; /* one-shot: the handler re-arms */
		bst_net_recv_ready_(s, events & (s->rslot.want | always), err);
	}
	if (!s->closed && m_send && s->wslot.armed) {
		s->wslot.armed = false;
		bst_net_send_ready_(s, events & (s->wslot.want | always), err);
	}
	if (!s->closed && m_poll && s->armed) {
		s->armed = false;
		s->cb(s->ud, events & (s->want | always), err);
	}
	if (!s->closed && s->kdisarmed)
		(void)sync_kernel(s, true); /* slots still waiting need the registration back */
}

void bst_sock_release_(bst_sock *s)
{
	if (s->inflight > 0)
		s->inflight--;
}

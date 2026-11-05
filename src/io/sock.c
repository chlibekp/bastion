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
	*s = (bst_sock){.loop = l, .fd = fd};
	return s;
}

void bst_sock_close(bst_sock *s)
{
	if (s == NULL || s->closed)
		return;
	bst_loop *l = s->loop;
	s->closed = true;
	s->armed = false;
	l->ops->sock_detach(s);
	close(s->fd);
	s->fd = -1;
	/* Freed at the end of the iteration: the current batch may still point at s. */
	s->dnext = l->dead;
	l->dead = s;
}

int bst_io_poll(bst_sock *s, uint32_t events, bst_poll_cb cb, void *ud)
{
	if (s->closed)
		return -EBADF;
	int rc = s->loop->ops->poll_arm(s, events);
	if (rc != 0)
		return rc;
	s->cb = cb;
	s->ud = ud;
	s->armed = true;
	return 0;
}

void bst_sock_ready_(bst_sock *s, uint32_t events)
{
	if (s->closed || !s->armed)
		return;
	s->armed = false; /* one-shot: the callback may re-arm */
	int err = 0;
	if (events & POLLERR) {
		socklen_t len = sizeof err;
		if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0)
			err = 0;
	}
	s->cb(s->ud, events, err);
}

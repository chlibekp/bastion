/* io_uring buffers: the loop's provided-buffer ring for recv, and the pipe pool for
 * splicing file segments.
 *
 * Buffer ring: nbufs slots of BST_RECV_BUF_SIZE, one bst_ubuf header per slot. The kernel
 * takes a slot when a recv completes into it; the slot is out of the ring ("taken") until
 * it comes back: recycled at once when no caller sees it (stale or closed socket), handed
 * to a caller as a bst_buf (bst_buf_init over the slot's header) and returned by the
 * release hook at its last unref, or copied out (BST_URING_COPY_MAX, pressure) into a
 * slab buffer and recycled at once. Copy-out keeps callers that hold buffers from
 * emptying the ring, which every socket of the loop shares.
 *
 * Pipes: a file segment goes file -> pipe -> socket. At most BST_URING_PIPES_MAX are in
 * use; past that, or when the kernel will not give a pipe of BST_URING_PIPE_MIN, the send
 * uses sendfile. A pipe that ends a send empty goes back to a pool of at most
 * BST_URING_PIPES; one with bytes left (error or close mid splice) is closed. */
#include "io/uring_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned char *slot(const bst_uring *u, unsigned bid)
{
	return u->bmem + (size_t)bid * BST_RECV_BUF_SIZE;
}

static void ring_add(bst_uring *u, unsigned bid)
{
	io_uring_buf_ring_add(u->br, slot(u, bid), BST_RECV_BUF_SIZE, (unsigned short)bid,
			      io_uring_buf_ring_mask(u->nbufs), 0);
	io_uring_buf_ring_advance(u->br, 1);
}

int bst_ubufs_init_(bst_uring *u, unsigned n, bst_err *err)
{
	if (n == 0)
		n = BST_URING_BUFS_DEFAULT;
	if (n > BST_URING_BUFS_MAX)
		n = BST_URING_BUFS_MAX;
	unsigned p2 = 1;
	while (p2 < n)
		p2 <<= 1;
	n = p2;
	u->bmem = malloc((size_t)n * BST_RECV_BUF_SIZE);
	u->bhdr = calloc(n, sizeof *u->bhdr);
	if (u->bmem == NULL || u->bhdr == NULL) {
		bst_err_set(err, "out of memory");
		return -ENOMEM;
	}
	int rc = 0;
	u->br = io_uring_setup_buf_ring(&u->ring, n, BST_URING_BGID, 0, &rc);
	if (u->br == NULL) {
		bst_err_set(err, "io_uring provided-buffer ring: %s", strerror(-rc));
		return rc != 0 ? rc : -ENOMEM;
	}
	u->nbufs = n;
	for (unsigned i = 0; i < n; i++) {
		u->bhdr[i].u = u;
		u->bhdr[i].bid = (uint16_t)i;
		io_uring_buf_ring_add(u->br, slot(u, i), BST_RECV_BUF_SIZE, (unsigned short)i,
				      io_uring_buf_ring_mask(n), (int)i);
	}
	io_uring_buf_ring_advance(u->br, (int)n);
	return 0;
}

void bst_ubufs_free_(bst_uring *u)
{
	if (u->leak)
		return; /* the kernel may still write into them */
	if (u->br != NULL &&
	    io_uring_free_buf_ring(&u->ring, u->br, u->nbufs, BST_URING_BGID) != 0)
		/* Unregistering was refused (a restricted ring): the ring's teardown drops it,
		 * and its pages stay pinned until then. */
		munmap(u->br, (size_t)u->nbufs * sizeof(struct io_uring_buf));
	u->br = NULL;
	free(u->bmem);
	free(u->bhdr);
	u->bmem = NULL;
	u->bhdr = NULL;
}

bst_ubuf *bst_ubufs_take_(bst_uring *u, unsigned bid, size_t len)
{
	if (bid >= u->nbufs)
		return NULL;
	bst_ubuf *b = &u->bhdr[bid];
	b->b.data = slot(u, bid);
	b->b.len = len;
	return b;
}

void bst_ubufs_recycle_(bst_uring *u, bst_ubuf *b)
{
	if (b == NULL)
		return;
	ring_add(u, b->bid);
	u->taken--;
	u->breturned = true;
}

static void ubuf_release(bst_buf *b, void *ctx)
{
	bst_uring *u = ctx;
	u->bout--;
	bst_ubufs_recycle_(u, (bst_ubuf *)b); /* b is the header's first member */
}

bst_buf *bst_ubufs_hand_(bst_uring *u, bst_ubuf *b)
{
	size_t len = b->b.len;
	bst_buf_init(&b->b, slot(u, b->bid), BST_RECV_BUF_SIZE, ubuf_release, u);
	b->b.len = len;
	u->bout++;
	return &b->b;
}

bst_buf *bst_ubufs_copy_(bst_uring *u, bst_ubuf *b)
{
#ifdef BST_TEST
	if (bst_test_uring_copy_fail > 0) {
		bst_test_uring_copy_fail--;
		return NULL;
	}
#endif
	bst_buf *c = bst_net_rbuf_(u->loop);
	if (c == NULL)
		return NULL;
	memcpy(c->data, slot(u, b->bid), b->b.len);
	c->len = b->b.len;
	bst_ubufs_recycle_(u, b);
#ifdef BST_TEST
	bst_test_uring_copies++;
#endif
	return c;
}

bool bst_ubufs_pressed_(const bst_uring *u)
{
	return u->taken >= u->nbufs / 2;
}

unsigned bst_ubufs_avail_(const bst_uring *u)
{
	return u->nbufs - u->taken;
}

bst_upipe *bst_upipe_get_(bst_uring *u, int *err)
{
	unsigned max = BST_URING_PIPES_MAX;
#ifdef BST_TEST
	if (bst_test_uring_pipes_max != 0)
		max = bst_test_uring_pipes_max;
#endif
	if (u->pipes_used >= max) {
		*err = -EBUSY;
		return NULL;
	}
	bst_upipe *p = u->pipes;
	if (p != NULL) {
		u->pipes = p->next;
		u->npipes--;
		u->pipes_used++;
		return p;
	}
	p = malloc(sizeof *p);
	if (p == NULL) {
		*err = -ENOMEM;
		return NULL;
	}
	int fds[2];
	if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) {
		*err = -errno;
		free(p);
		return NULL;
	}
	/* Over the per-user pipe page limit the kernel hands out tiny pipes: those are not
	 * kept (a capacity is never cached below BST_URING_PIPE_MIN), sendfile takes over. */
	(void)fcntl(fds[1], F_SETPIPE_SZ, (int)BST_URING_PIPE_SIZE);
	int cap = fcntl(fds[1], F_GETPIPE_SZ);
	if (cap < (int)BST_URING_PIPE_MIN) {
		close(fds[0]);
		close(fds[1]);
		free(p);
		*err = -ENOBUFS;
		return NULL;
	}
	p->rd = fds[0];
	p->wr = fds[1];
	p->cap = (size_t)cap;
	p->next = NULL;
	u->pipes_used++;
#ifdef BST_TEST
	bst_test_uring_pipes_made++;
#endif
	return p;
}

void bst_upipe_put_(bst_uring *u, bst_upipe *p, bool empty)
{
	if (p == NULL)
		return;
	u->pipes_used--;
	if (empty && u->npipes < BST_URING_PIPES) {
		p->next = u->pipes;
		u->pipes = p;
		u->npipes++;
		return;
	}
	close(p->rd);
	close(p->wr);
	free(p);
}

void bst_upipes_free_(bst_uring *u)
{
	while (u->pipes != NULL) {
		bst_upipe *p = u->pipes;
		u->pipes = p->next;
		close(p->rd);
		close(p->wr);
		free(p);
	}
	u->npipes = 0;
}

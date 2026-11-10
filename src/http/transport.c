#include "http/transport.h"

#include <stdlib.h>

typedef struct plain {
	bst_transport base;
	bst_sock *s;
} plain;

static int plain_recv_start(bst_transport *t, bst_recv_cb cb, void *ud)
{
	return bst_io_recv_start(((plain *)t)->s, cb, ud);
}

static int plain_recv_stop(bst_transport *t)
{
	return bst_io_recv_stop(((plain *)t)->s);
}

static int plain_send(bst_transport *t, bst_chain *c, bst_done_cb cb, void *ud)
{
	return bst_io_send(((plain *)t)->s, c, cb, ud);
}

static bool plain_zero_copy(const bst_transport *t)
{
	(void)t;
	return true;
}

static void plain_shutdown(bst_transport *t, bst_done_cb cb, void *ud)
{
	int rc = bst_sock_shutdown_wr(((plain *)t)->s);
	if (cb != NULL)
		cb(ud, 0, rc);
}

static void plain_close(bst_transport *t)
{
	plain *p = (plain *)t;
	bst_sock_close(p->s);
	free(p);
}

static const bst_transport_ops plain_ops = {
	.recv_start = plain_recv_start,
	.recv_stop = plain_recv_stop,
	.send = plain_send,
	.zero_copy_files = plain_zero_copy,
	.shutdown = plain_shutdown,
	.close = plain_close,
};

bst_transport *bst_transport_plain(bst_sock *s)
{
	plain *p = malloc(sizeof *p);
	if (p == NULL)
		return NULL;
	p->base.ops = &plain_ops;
	p->s = s;
	return &p->base;
}

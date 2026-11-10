/* What HTTP/1.1 and HTTP/2 talk to instead of a socket (architecture section 5), so one
 * protocol implementation runs over cleartext or TLS. Phase 4 provides the plain transport; the
 * TLS one of Phase 6 implements the same ops. Single loop thread. */
#ifndef BST_HTTP_TRANSPORT_H
#define BST_HTTP_TRANSPORT_H

#include "io/net.h"

#include <stdbool.h>

typedef struct bst_transport bst_transport;

typedef struct bst_transport_ops {
	int (*recv_start)(bst_transport *, bst_recv_cb, void *ud);
	int (*recv_stop)(bst_transport *);
	int (*send)(bst_transport *, bst_chain *, bst_done_cb, void *ud);
	bool (*zero_copy_files)(const bst_transport *); /* cleartext or kTLS TX */
	/* Ends the sending direction and tells the peer (a half-close for plain TCP, close_notify for
	 * TLS). The done callback may run before this returns. The transport still reads. */
	void (*shutdown)(bst_transport *, bst_done_cb, void *ud);
	/* Closes and frees it, cancelling everything pending: no callback runs afterwards. */
	void (*close)(bst_transport *);
} bst_transport_ops;

struct bst_transport {
	const bst_transport_ops *ops;
};

/* A transport over a connected socket, which it then owns. NULL on exhaustion (the socket is
 * not consumed). */
bst_transport *bst_transport_plain(bst_sock *s);

#endif

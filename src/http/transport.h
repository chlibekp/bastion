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

/* The per-connection facts every protocol shares sit here, zeroed by each constructor. */
struct bst_transport {
	const bst_transport_ops *ops;
	/* The client address came from a PROXY protocol header (proxy/proxyproto.h), not from the
	 * socket: the peer is a trusted balancer, so per-address escalation (Phase 12, XDP) must
	 * not act on the socket's address. */
	bool client_addr_from_header;
	/* The address the client connected to: the PROXY header's destination, else getsockname at
	 * accept. Valid when has_local; sent upstream by `send_proxy_protocol`. */
	bool has_local;
	bst_sockaddr local;
};

/* A transport over a connected socket, which it then owns. NULL on exhaustion (the socket is
 * not consumed). */
bst_transport *bst_transport_plain(bst_sock *s);

#endif

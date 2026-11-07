/* The master channel: one SOCK_SEQPACKET socketpair per child, with typed messages.
 *
 * A child writes these and master, which is root, reads them, so master treats every datagram
 * as hostile. A message is an exact byte layout: magic, type, payload length, payload. Decoding
 * accepts only a known type, whose length is exactly that type's, and whose values are in
 * range; anything else is a refusal, and master answers a refusal by killing the sender.
 * Nothing in a message names a slot: master knows who wrote it from the channel it read. */
#ifndef BST_PROC_CHANNEL_H
#define BST_PROC_CHANNEL_H

#include "io/backend_kind.h"

#include <stdbool.h>
#include <stddef.h>

#define BST_CHAN_MAX 16u /* bytes on the wire, longest message */
#define BST_CHAN_HDR 4u  /* magic (2), type, payload length */

typedef enum bst_msg_type {
	BST_MSG_READY = 1, /* child to master: started, with the backend of its loop */
	BST_MSG_STOP = 2,  /* master to child */
} bst_msg_type;

typedef struct bst_msg {
	bst_msg_type type;
	union {
		struct {
			bst_backend backend; /* URING or EPOLL, never AUTO */
		} ready;
		struct {
			bool graceful; /* finish what is in flight, or exit now */
		} stop;
	};
} bst_msg;

/* Bytes written to buf, or 0 when cap is too small or m is not a valid message. */
size_t bst_chan_encode(const bst_msg *m, void *buf, size_t cap);
/* True when buf[0..len-1] is exactly one valid message. */
bool bst_chan_decode(const void *buf, size_t len, bst_msg *out);

/* A pair of non-blocking, close-on-exec SOCK_SEQPACKET sockets. 0, or -1 with errno set. */
int bst_chan_pair(int sv[2]);
/* 0, or a negative errno (-EAGAIN when the peer's queue is full). Never blocks. */
int bst_chan_send(int fd, const bst_msg *m);
/* One datagram: 1 with *out set, 0 at EOF (ECONNRESET included), -EAGAIN with nothing queued, -EPROTO for a malformed
 * message (it is consumed; an oversized one is refused whole), or another negative errno. File
 * descriptors passed with a datagram are discarded by the kernel: no control buffer is given. */
int bst_chan_recv(int fd, bst_msg *out);

#endif

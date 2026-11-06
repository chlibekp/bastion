/* Stream I/O on loop sockets: accept, recv, send (with file segments) and connect.
 * Architecture section 3. Callbacks run on the loop thread. Errors are reported as
 * negative errno values (0 is success), unlike bst_poll_cb whose err is SO_ERROR.
 *
 * Per socket there is one recv stream, one send-or-connect operation and one poll, each
 * with its own readiness slot, so all three may be outstanding together. bst_sock_close
 * cancels everything: after it returns, no callback of this module runs for the socket
 * (no recv_cb, no done_cb, no accept_cb), and an operation still in flight completes
 * silently, so a caller that needs to know must not close until the completion ran.
 *
 * Closing and the peer. On io_uring the fd number is closed at once, but the kernel socket
 * lives on while a request on it is in flight, so the peer sees the close only after the
 * loop next runs (see bst_loop_free in loop.h). A thread blocked in write(2) on the peer's
 * other end is not woken by a close(2) from another thread either: shutdown(2) it. */
#ifndef BST_IO_NET_H
#define BST_IO_NET_H

#include "core/addr.h"
#include "core/buf.h"
#include "core/chain.h"
#include "io/aio.h"
#include "io/sock.h"

#include <stddef.h>

#define BST_RECV_BUF_SIZE 16384u /* bytes per recv buffer, taken from a per-loop slab */
#define BST_RECV_BUDGET 4u       /* reads per readiness event before yielding to other sockets */
#define BST_ACCEPT_BUDGET 64u    /* accepts per readiness event */
#define BST_SEND_CHUNK (1u << 20)   /* largest single sendfile */
#define BST_SEND_BUDGET (4u << 20)  /* bytes per readiness event before yielding */
#define BST_PROBE_STRIDE (256u << 10) /* residency probe spacing inside a chunk */

/* peer is NULL for a non-IP peer. err < 0 means accepting failed: fd is -1. EMFILE and
 * ENFILE (and any other unexpected error) PAUSE accepting: no further callback until the
 * callback itself, or later code, calls bst_io_accept_start on the same fd again (policy
 * is Task 9's). Never a busy loop. The callback owns fd. */
typedef void (*bst_accept_cb)(void *ud, int fd, const bst_sockaddr *peer, int err);
/* data is one buffer with len > 0 and one reference the callback owns (bst_buf_unref
 * it; do it before bst_loop_free). (NULL, 0) is EOF, (NULL, -errno) an error; both end
 * the stream (call bst_io_recv_start for more). Holding recv buffers never stalls other
 * sockets, on either backend: holding costs memory, not shared receive resources (io_uring
 * copies a small payload, or any payload once half the loop's provided-buffer ring is out,
 * into a slab buffer and gives the ring slot back at once). */
typedef void (*bst_recv_cb)(void *ud, bst_buf *data, int err);
/* bytes written by this operation, err 0 or -errno. */
typedef void (*bst_done_cb)(void *ud, size_t bytes, int err);

/* Accepts on listen_fd (borrowed: never closed here; made non-blocking) until EAGAIN, at
 * most BST_ACCEPT_BUDGET per wakeup. -EEXIST while already accepting on that fd. */
int bst_io_accept_start(bst_loop *l, int listen_fd, bst_accept_cb cb, void *ud);
/* Stops and forgets the listener. 0, or -ENOENT. No callback after it returns, so on io_uring a
 * connection already accepted whose completion is not delivered yet is closed. */
int bst_io_accept_stop(bst_loop *l, int listen_fd);
/* Stops accepting and loses nothing in flight, for a graceful stop. 0: stopped and forgotten
 * now, as by bst_io_accept_stop (epoll, which has nothing in flight). 1: connections already
 * accepted still reach the callback, then it runs once more with (fd -1, err -ECANCELED) and
 * nothing follows; call bst_io_accept_stop from there or later, to forget the listener.
 * -ENOENT: not a listener. May be called from the callback. */
int bst_io_accept_quiesce(bst_loop *l, int listen_fd);

/* Accepts what is already queued on listen_fd, now, up to max connections, handing each to cb
 * like bst_io_accept_start would. Returns the count. A stopping worker uses it to take what the
 * kernel completed before the socket goes, and a worker on io_uring to sweep for a connection
 * whose wakeup went to a dead ring (architecture section 4). */
unsigned bst_io_accept_drain(int listen_fd, bst_accept_cb cb, void *ud, unsigned max);

/* One recv stream per socket: -EBUSY while one runs. Reads loop until EAGAIN, at most
 * BST_RECV_BUDGET per wakeup. Stop is immediate: no callback after it returns. */
int bst_io_recv_start(bst_sock *s, bst_recv_cb cb, void *ud);
int bst_io_recv_stop(bst_sock *s);

/* Writes the whole chain, then calls done exactly once (never from inside this call,
 * also for an empty chain, an error, a reset or a peer close). Memory segments go out
 * with sendmsg(MSG_NOSIGNAL), file segments with sendfile; no path raises SIGPIPE
 * once bst_io_ignore_sigpipe has run. On io_uring memory goes out with SENDMSG (SENDMSG_ZC
 * from uring_send_zc_min bytes) and file segments are spliced through a pooled pipe, or
 * sent with sendfile when splice is refused or pipes run short. Zero-copy holds its own
 * reference on each buffer until the kernel is done with the pages; closing a socket with
 * zero-copy pages still queued aborts the connection (RST), so caller memory rewritten
 * after close does not reach the peer. Best effort: the RST drops what TCP still holds, but
 * a packet already handed to the device queue may go out with the bytes it had.
 * Bytes are consumed from the chain as they are written, so buffer references drop at
 * once. The caller owns the chain and keeps it valid until done runs (or the socket is
 * closed, after which the module no longer touches it). One send or connect at a time:
 * a second returns -EBUSY. A file that ends before its segment does completes with -EIO.
 * File pages are checked with preadv2(RWF_NOWAIT); cold ones are read ahead on the aio
 * pool first, so the loop thread does not wait on the disk. */
int bst_io_send(bst_sock *s, bst_chain *c, bst_done_cb cb, void *ud);

/* Non-blocking connect; done(0, result) when the connection is established or failed
 * (result from SO_ERROR, for instance -ECONNREFUSED). Occupies the send slot (-EBUSY if
 * a send is in flight). Timeouts belong to the caller: arm a timer and bst_sock_close. */
int bst_io_connect(bst_sock *s, const bst_sockaddr *to, bst_done_cb cb, void *ud);

/* Makes SIGPIPE ignored process-wide (sigaction SIG_IGN). Master, workers and helper call
 * it once at start; unit tests call it in setup. sendmsg also passes
 * MSG_NOSIGNAL, but sendfile has no such flag, so the disposition is what protects it. */
void bst_io_ignore_sigpipe(void);

#ifdef BST_TEST
extern int bst_test_ra_jobs;     /* readahead jobs started (loop thread only) */
extern unsigned bst_test_send_budget; /* if nonzero, replaces BST_SEND_BUDGET */
#endif

#endif

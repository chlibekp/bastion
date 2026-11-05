/* Loop-registered sockets. */
#ifndef BST_IO_SOCK_H
#define BST_IO_SOCK_H

#include "io/loop.h"

typedef struct bst_sock bst_sock;

/* Events are poll(2) flags (POLLIN, POLLOUT, POLLRDHUP); POLLERR and POLLHUP are always
 * reported. On POLLERR, err is the socket's SO_ERROR (else 0). */
typedef void (*bst_poll_cb)(void *ud, uint32_t events, int err);

/* Takes ownership of fd and makes it non-blocking. NULL on failure (fd not consumed). */
bst_sock *bst_sock_wrap(bst_loop *l, int fd);

/* Closes the fd and cancels all pending operations. No callback for this socket runs
 * after it returns, including one for an event already fetched in the current batch. The
 * object is freed at the end of the loop iteration, so it may be called from any callback
 * (its own included). The pointer is invalid afterwards. NULL is ignored. */
void bst_sock_close(bst_sock *s);

/* One-shot readiness: bst_poll_cb runs once when any of events is ready, then the poll is
 * disarmed; call again to re-arm. Re-arming reports readiness that already exists (data
 * that arrived since the last callback is not lost). Replaces a pending poll. 0 or -errno.
 * Implemented as edge-triggered EPOLLET|EPOLLONESHOT on epoll. */
int bst_io_poll(bst_sock *s, uint32_t events, bst_poll_cb cb, void *ud);

#endif

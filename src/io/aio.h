/* Fixed thread pool for blocking work (disk reads, readahead). Created by bst_loop_new
 * from bst_loop_cfg, before any sandbox exists, because the sandbox later forbids
 * thread creation. */
#ifndef BST_IO_AIO_H
#define BST_IO_AIO_H

#include "io/loop.h"

#define BST_AIO_THREADS_DEFAULT 4u   /* used when bst_loop_cfg.aio_threads is 0 */
#define BST_AIO_THREADS_MAX 64u      /* larger requests are clamped */
#define BST_AIO_QUEUE_DEFAULT 256u   /* used when bst_loop_cfg.aio_queue is 0 */
#define BST_AIO_QUEUE_MAX 65536u
#define BST_AIO_STACK_SIZE (256u * 1024u) /* set explicitly: musl's default is 128 KiB */

/* Queues work(arg) to run on a pool thread, then done(arg) on the loop thread (done may
 * be NULL). Thread-safe. Returns 0, -EAGAIN when queue-depth jobs are already queued,
 * running or waiting for their done (the queue is bounded, never grows), -EINVAL for a
 * NULL work, or -ESHUTDOWN once bst_loop_free has begun.
 *
 * done is called exactly once for every accepted job, in completion order, on the loop
 * thread. Shutdown: bst_loop_free stops intake, lets the workers finish every queued
 * job, joins them, then runs the remaining done callbacks on the thread calling
 * bst_loop_free. No accepted job is dropped. A done callback running at that point must
 * not submit work (it gets -ESHUTDOWN) and must not use closed sockets. */
int bst_aio_submit(bst_loop *l, void (*work)(void *), void (*done)(void *), void *arg);

#endif

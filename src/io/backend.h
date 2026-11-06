/* Choosing and reporting the I/O backend. The loop itself selects (bst_loop_new, io/loop.h);
 * this is the config-facing side: the loop configuration built from a compiled io { }
 * block, the one-line report shared by `bastion -t` and worker start, and the
 * bastion_io_backend{name} metric. */
#ifndef BST_IO_BACKEND_H
#define BST_IO_BACKEND_H

#include "config/compile.h"
#include "io/loop.h"

#include <stddef.h>

#define BST_AIO_THREADS_AUTO_MAX 8u /* `aio_threads auto`: CPU count, at most this many */
#define BST_URING_NAPI_US 50u       /* busy-poll timeout used by `uring_napi on` */

const char *bst_backend_name(bst_backend b);

/* `aio_threads auto` for a machine with cpus CPUs: at least 1, at most BST_AIO_THREADS_AUTO_MAX. */
unsigned bst_io_aio_auto(unsigned cpus);

/* Registers bastion_io_backend{name=uring} and {name=epoll} (value: event loops running on
 * that backend, summed over this process's lifetime). Call once at startup in the master,
 * before workers fork: the counters table has a single registering writer and registration
 * from loop threads would race. Idempotent. */
void bst_io_backend_init(void);

/* The loop configuration of a compiled config: the one function workers and `-t` use. */
void bst_io_loop_cfg(const bst_config *cfg, bst_loop_cfg *out);

/* "io backend: <name> (<reason>)", for the backend l actually runs. Returns the length. */
size_t bst_io_backend_line(const bst_loop *l, char *buf, size_t cap);
/* Logs that line at info level and counts bastion_io_backend{name=<backend>}. Worker start
 * calls this once per loop. */
void bst_io_backend_report(const bst_loop *l);

/* Creates and frees a loop exactly as a worker would, to learn what it would get. 0 with the
 * report line in line, or -1 with err set (backend uring unavailable, a required feature
 * missing). */
int bst_io_probe(const bst_config *cfg, char *line, size_t cap, bst_err *err);

#endif

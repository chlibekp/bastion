/* See backend.h. */
#include "io/backend.h"

#include "core/counters.h"
#include "core/log.h"

#include <sched.h>
#include <stdio.h>
#include <unistd.h>

const char *bst_backend_name(bst_backend b)
{
	switch (b) {
	case BST_BACKEND_URING:
		return "uring";
	case BST_BACKEND_EPOLL:
		return "epoll";
	default:
		return "auto";
	}
}

static unsigned cpu_count(void)
{
	cpu_set_t set;
	if (sched_getaffinity(0, sizeof set, &set) == 0) {
		int n = CPU_COUNT(&set);
		if (n > 0)
			return (unsigned)n;
	}
	long n = sysconf(_SC_NPROCESSORS_ONLN);
	return n > 0 ? (unsigned)n : 1u;
}

void bst_io_loop_cfg(const bst_config *cfg, bst_loop_cfg *out)
{
	const bst_cfg_io *io = &cfg->global.io;
	*out = (bst_loop_cfg){0};
	out->backend = io->backend;
	out->uring_entries = io->uring_entries;
	out->uring_bufs = io->uring_bufs;
	out->uring_sqpoll = io->sqpoll_ms;
	out->uring_napi = io->napi ? BST_URING_NAPI_US : 0;
	out->uring_napi_require = io->napi_require;
	out->uring_send_zc_min = (size_t)io->send_zc_min;
	unsigned t = io->aio_threads;
	if (io->aio_auto) {
		t = cpu_count();
		if (t > BST_AIO_THREADS_AUTO_MAX)
			t = BST_AIO_THREADS_AUTO_MAX;
	}
	out->aio_threads = t;
	out->aio_queue = io->aio_queue;
}

size_t bst_io_backend_line(const bst_loop *l, char *buf, size_t cap)
{
	int n = snprintf(buf, cap, "io backend: %s (%s)", bst_backend_name(bst_loop_backend(l)),
			 bst_loop_backend_reason(l));
	return n < 0 ? 0 : (size_t)n < cap ? (size_t)n : cap - 1;
}

void bst_io_backend_report(const bst_loop *l)
{
	char line[256];
	bst_io_backend_line(l, line, sizeof line);
	bst_log(BST_LOG_INFO, "%s", line);
	char label[32];
	snprintf(label, sizeof label, "name=%s", bst_backend_name(bst_loop_backend(l)));
	bst_counter_add(bst_counter_register("bastion_io_backend",
					     "I/O backend in use (1 for the running backend)", label),
			1);
}

int bst_io_probe(const bst_config *cfg, char *line, size_t cap, bst_err *err)
{
	bst_loop_cfg lc;
	bst_io_loop_cfg(cfg, &lc);
	bst_loop *l = bst_loop_new(&lc, err);
	if (l == NULL)
		return -1;
	bst_io_backend_line(l, line, cap);
	bst_loop_free(l);
	return 0;
}

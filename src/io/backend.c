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

unsigned bst_io_cpu_count(void)
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

unsigned bst_io_aio_auto(unsigned cpus)
{
	if (cpus < 1)
		return 1;
	return cpus > BST_AIO_THREADS_AUTO_MAX ? BST_AIO_THREADS_AUTO_MAX : cpus;
}

static bst_counter_id backend_ctr[3] = {BST_COUNTER_INVALID, BST_COUNTER_INVALID,
					BST_COUNTER_INVALID};

void bst_io_backend_init(void)
{
	static const bst_backend which[] = {BST_BACKEND_URING, BST_BACKEND_EPOLL};
	for (unsigned i = 0; i < 2; i++) {
		char label[32];
		snprintf(label, sizeof label, "name=%s", bst_backend_name(which[i]));
		backend_ctr[which[i]] = bst_counter_register(
			"bastion_io_backend", "number of event loops on this backend", label);
	}
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
	out->aio_threads = io->aio_auto ? bst_io_aio_auto(bst_io_cpu_count()) : io->aio_threads;
	out->aio_queue = io->aio_queue;
}

size_t bst_io_backend_line(const bst_loop *l, char *buf, size_t cap)
{
	if (cap == 0)
		return 0;
	int n = snprintf(buf, cap, "io backend: %s (%s)", bst_backend_name(bst_loop_backend(l)),
			 bst_loop_backend_reason(l));
	if (n < 0 || cap == 0)
		return 0;
	return (size_t)n < cap ? (size_t)n : cap - 1;
}

void bst_io_backend_report(const bst_loop *l)
{
	char line[256];
	bst_io_backend_line(l, line, sizeof line);
	bst_log(BST_LOG_INFO, "%s", line);
	bst_counter_add(backend_ctr[bst_loop_backend(l)], 1); /* INVALID before init: no-op */
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

int bst_io_probe_cfg(const bst_loop_cfg *lc, bst_backend *backend, char *reason, size_t cap,
		     bst_err *err)
{
	bst_loop *l = bst_loop_new(lc, err);
	if (l == NULL)
		return -1;
	*backend = bst_loop_backend(l);
	snprintf(reason, cap, "%s", bst_loop_backend_reason(l));
	bst_loop_free(l);
	return 0;
}

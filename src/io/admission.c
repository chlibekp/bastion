/* See admission.h. */
#include "io/admission.h"

#include "core/log.h"
#include "io/net.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void reserve_take(bst_admission *adm)
{
	for (unsigned i = 0; i < adm->lim->reserve_fds; i++) {
		if (adm->reserve[i] >= 0)
			continue;
		adm->reserve[i] = fcntl(adm->dup_src, F_DUPFD_CLOEXEC, 0);
		if (adm->reserve[i] < 0) {
			bst_log(BST_LOG_WARN, "reserve_fds: holding %u of %u descriptors: %s", i,
				adm->lim->reserve_fds, strerror(errno));
			return;
		}
	}
}

static void reserve_give(bst_admission *adm)
{
	for (unsigned i = 0; i < adm->lim->reserve_fds; i++)
		if (adm->reserve[i] >= 0) {
			close(adm->reserve[i]);
			adm->reserve[i] = -1;
		}
}

void bst_adm_init(bst_admission *adm, const bst_cfg_limits *lim, bst_loop *loop, int dup_src)
{
	memset(adm, 0, sizeof *adm);
	adm->lim = lim;
	adm->loop = loop;
	adm->dup_src = dup_src;
	bst_timer_init(&adm->report);
	for (size_t i = 0; i < BST_LIMITS_RESERVE_FDS_MAX; i++)
		adm->reserve[i] = -1;
	reserve_take(adm);
}

/* One line per period, armed by the first event of it: a flood logs once a second, not once an
 * event. The figures are totals, so the line says what happened since start. */
static void report(void *ud)
{
	bst_admission *a = ud;
	a->report_armed = false;
	unsigned long long c = atomic_load_explicit(&a->closed, memory_order_relaxed);
	unsigned long long r = atomic_load_explicit(&a->refused, memory_order_relaxed);
	unsigned long long f = atomic_load_explicit(&a->fd_closed, memory_order_relaxed);
	bst_log(BST_LOG_WARN,
		"overload: closed=%llu connections over max_connections, refused=%llu requests over "
		"worker_memory, fd_closed=%llu connections at the descriptor limit (totals since "
		"start)",
		c, r, f);
}

static void noted(bst_admission *a)
{
	if (a->report_armed)
		return;
	a->report_armed = true;
	bst_loop_timer_arm(a->loop, &a->report, BST_ADM_REPORT_MS, report, a);
}

bool bst_adm_admit(bst_admission *adm, unsigned long long conns)
{
	if (conns < adm->lim->max_connections)
		return true;
	atomic_fetch_add_explicit(&adm->closed, 1, memory_order_relaxed);
	noted(adm);
	return false;
}

bool bst_adm_mem_charge(bst_admission *adm, size_t n)
{
	size_t used = atomic_load_explicit(&adm->mem_used, memory_order_relaxed);
	do {
		if (n > adm->lim->worker_memory || used > adm->lim->worker_memory - n)
			return false;
	} while (!atomic_compare_exchange_weak_explicit(&adm->mem_used, &used, used + n,
							memory_order_relaxed, memory_order_relaxed));
	return true;
}

void bst_adm_mem_release(bst_admission *adm, size_t n)
{
	size_t used = atomic_load_explicit(&adm->mem_used, memory_order_relaxed);
	size_t left;
	do {
		left = used >= n ? used - n : 0; /* a release without its charge is a caller's bug */
	} while (!atomic_compare_exchange_weak_explicit(&adm->mem_used, &used, left,
							memory_order_relaxed, memory_order_relaxed));
	if (n > used)
		bst_log(BST_LOG_ERROR, "memory budget: released %zu bytes of %zu charged", n, used);
}

bool bst_adm_overloaded(const bst_admission *adm)
{
	return atomic_load_explicit(&adm->mem_used, memory_order_relaxed) >= adm->lim->worker_memory;
}

void bst_adm_refused(bst_admission *adm)
{
	atomic_fetch_add_explicit(&adm->refused, 1, memory_order_relaxed);
	noted(adm);
}

static void shed_one(void *ud, int fd, const bst_sockaddr *peer, int err)
{
	(void)peer, (void)err;
	close(fd);
	(void)ud;
}

unsigned bst_adm_shed_fds(bst_admission *adm, int listen_fd)
{
	reserve_give(adm);
	/* Each accepted descriptor is closed before the next accept, so one freed slot serves
	 * them all. */
	unsigned n = bst_io_accept_drain(listen_fd, shed_one, adm, BST_ADM_SHED_MAX);
	reserve_take(adm);
	if (n > 0) {
		atomic_fetch_add_explicit(&adm->fd_closed, n, memory_order_relaxed);
		noted(adm);
	}
	return n;
}

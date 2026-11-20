/* worker_cpu_affinity, numa, huge_pages and epoll_busy_poll (ops/numa.h). */
#include "config/compile.h"
#include "config/values.h"
#include "core/str.h"
#include "ops/numa.h"

#include <stdlib.h>
#include <string.h>

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static bst_cfg_tuning *T(bst_cfg_ctx *c, bst_err *e)
{
	if (c->global->tuning == NULL) {
		bst_cfg_tuning *t = bst_arena_alloc(c->arena, sizeof *t);
		if (t == NULL) {
			bst_err_set(e, "out of memory");
			return NULL;
		}
		*t = *bst_tuning(&(bst_config){ 0 }); /* the defaults */
		c->global->tuning = t;
	}
	return c->global->tuning;
}

static bool cpu_num(const char *p, size_t n, int *out)
{
	int64_t v;
	if (!bst_parse_int((bst_str){ p, (uint32_t)n }, 0, BST_CPU_LIST_MAX - 1, &v))
		return false;
	*out = (int)v;
	return true;
}

static int ap_affinity(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_tuning *t = T(c, e);
	if (t == NULL || bst_cfg_loc_at(c, &n->loc, &t->affinity_loc, e) != 0)
		return -1;
	size_t na = bst_dir_npos(d, n);
	if (na == 1 && bst_str_eq(as_str(bst_dir_pos(d, n, 0)), BST_S("auto"))) {
		t->affinity = BST_AFFINITY_AUTO;
		return 0;
	}
	int allowed[BST_CPU_LIST_MAX];
	size_t nallowed = bst_cpus_allowed(allowed, BST_CPU_LIST_MAX);
	int *list = bst_arena_alloc(c->arena, BST_CPU_LIST_MAX * sizeof *list);
	size_t cnt = 0;
	if (list == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	for (size_t i = 0; i < na; i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		const char *dash = memchr(a->text, '-', a->len);
		int lo, hi;
		bool ok = dash != NULL ? cpu_num(a->text, (size_t)(dash - a->text), &lo) &&
						 cpu_num(dash + 1, a->len - (size_t)(dash - a->text) - 1, &hi) && lo <= hi
				       : cpu_num(a->text, a->len, &lo);
		if (dash == NULL)
			hi = lo;
		if (!ok) {
			bst_err_set(e, "worker_cpu_affinity: auto, or CPU numbers and ranges such as 0 2 4-7");
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		for (int cpu = lo; cpu <= hi; cpu++) {
			bool found = false;
			for (size_t k = 0; k < nallowed; k++)
				found |= allowed[k] == cpu;
			if (!found) {
				bst_err_set(e, "worker_cpu_affinity: CPU %d is not available to this process "
					       "(offline, or outside its cpuset)", cpu);
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
			if (cnt == BST_CPU_LIST_MAX) {
				bst_err_set(e, "worker_cpu_affinity: at most %d CPUs", BST_CPU_LIST_MAX);
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
			list[cnt++] = cpu;
		}
	}
	t->affinity = BST_AFFINITY_LIST;
	t->cpus = list;
	t->ncpus = cnt;
	return 0;
}

static const char *const numa_values[] = { "auto", "off", NULL };
static const char *const huge_values[] = { "off", "auto", "on", NULL };

static int ap_numa(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_tuning *t = T(c, e);
	if (t == NULL)
		return -1;
	size_t i = 0;
	(void)bst_parse_enum(as_str(bst_dir_pos(d, n, 0)), numa_values, &i);
	t->numa = i == 0;
	return 0;
}

static int ap_huge(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_tuning *t = T(c, e);
	if (t == NULL)
		return -1;
	size_t i = 0;
	(void)bst_parse_enum(as_str(bst_dir_pos(d, n, 0)), huge_values, &i);
	t->huge_pages = (bst_huge_pages)i;
	return 0;
}

static int ap_epoll_busy(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_tuning *t = T(c, e);
	if (t == NULL)
		return -1;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	uint64_t us = 0;
	(void)bst_parse_duration_us(as_str(a), &us);
	if (us > 1000000) {
		bst_err_set(e, "epoll_busy_poll: at most 1s");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	t->epoll_busy_poll_us = (unsigned)us;
	return 0;
}

static const bst_directive tuning_dirs[] = {
	{ .name = "worker_cpu_affinity", .contexts = BST_CTX_GLOBAL, .apply = ap_affinity,
	  .doc = "Pins worker slot i to a CPU: auto takes the CPUs this process may run on (its "
		 "cpuset) in order, a list (0 2 4-7) takes those, both modulo their count. Without it, "
		 "workers are pinned only when a listener uses `steering incoming_cpu` or `ebpf`, as "
		 "with auto. Listener steering follows the same map.",
	  .args = { .min_args = 1, .max_args = 64, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "numa", .contexts = BST_CTX_GLOBAL, .apply = ap_numa, .default_value = "auto",
	  .doc = "auto: on a machine with more than one NUMA node, the automatic CPU map fills one "
		 "node before the next, so neighbouring workers share a node. Nothing changes on a "
		 "single node.",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = numa_values } } } },
	{ .name = "huge_pages", .contexts = BST_CTX_GLOBAL, .apply = ap_huge, .default_value = "off",
	  .doc = "auto or on: the allocator asks for transparent huge pages when the kernel offers "
		 "them; otherwise normal pages, logged (a warning under on).",
	  .args = { .min_args = 1, .max_args = 1,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = huge_values } } } },
	{ .name = "epoll_busy_poll", .contexts = BST_CTX_IO, .apply = ap_epoll_busy, .default_value = "0s",
	  .doc = "epoll backend: busy-poll the NIC queue this long before sleeping (EPIOCSPARAMS, "
		 "Linux 6.9; an older kernel logs a warning). 0 is off. Pair with the listener's "
		 "busy_poll in a tcp_profile; io_uring has uring_napi instead.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_DURATION } } } },
};
BST_DIRECTIVES(tuning_dirs);

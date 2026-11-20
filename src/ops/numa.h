/* CPU placement, NUMA and huge pages (docs/tuning.md).
 *
 * The CPU map. Master builds it once, before any fork, from the CPUs this process may run on
 * (sched_getaffinity, so a container's cpuset is respected) and `worker_cpu_affinity`:
 *   - auto: slot i on the i-th allowed CPU, modulo their count;
 *   - a list: slot i on list[i % n], each CPU checked against the allowed set at load;
 *   - none, with a listener under `steering incoming_cpu` or `ebpf`: as auto.
 * bst_worker_cpu (proc/worker.c) pins by it and listener steering (io/sockopts.c) reads the same
 * map, so a worker always sits on the CPU its socket prefers. With `numa auto` and more than one
 * node, auto orders the allowed CPUs node by node, so neighbouring slots share a node.
 *
 * Huge pages. `huge_pages on|auto` asks the allocator for transparent huge pages (mimalloc's
 * large OS pages) when the kernel offers them (transparent_hugepage/enabled is not `never`);
 * otherwise it logs and uses normal pages (a warning under `on`). */
#ifndef BST_OPS_NUMA_H
#define BST_OPS_NUMA_H

#include "config/compile.h"

#include <stdbool.h>
#include <stddef.h>

#define BST_CPU_LIST_MAX 1024

typedef enum bst_affinity { BST_AFFINITY_NONE, BST_AFFINITY_AUTO, BST_AFFINITY_LIST } bst_affinity;
typedef enum bst_huge_pages { BST_HUGE_OFF, BST_HUGE_AUTO, BST_HUGE_ON } bst_huge_pages;

typedef struct bst_cfg_tuning {
	bst_affinity affinity;
	int *cpus; /* BST_AFFINITY_LIST */
	size_t ncpus;
	bool numa;		/* numa auto */
	bst_huge_pages huge_pages;
	unsigned epoll_busy_poll_us; /* 0: off */
	bst_cfg_loc affinity_loc;
} bst_cfg_tuning;

/* The tuning of a config, defaults when it has none of the directives. */
const bst_cfg_tuning *bst_tuning(const bst_config *cfg);

/* The CPUs this process may run on, ascending: their count (0 on failure). */
size_t bst_cpus_allowed(int *out, size_t cap);
/* NUMA node of a CPU from sysfs, -1 when unknown; and the number of online nodes (1 when sysfs
 * has none). */
int bst_numa_node_of(int cpu);
int bst_numa_nodes(void);

/* Master, before any fork: builds the map. pin: some listener steers by CPU. Returns whether
 * workers are pinned at all. */
bool bst_cpu_map_build(const bst_config *cfg, bool pin);
/* The CPU of a slot, -1 when slots are not pinned. */
int bst_cpu_map_slot(int slot);
/* How many CPUs the map cycles through (0 when not pinned). */
int bst_cpu_map_len(void);

/* Master, before any fork: applies huge_pages (inherited by every child). */
void bst_huge_pages_apply(const bst_config *cfg);
/* "always", "madvise" or "never" from the kernel, NULL when unknown. */
const char *bst_thp_mode(char *buf, size_t cap);

#endif

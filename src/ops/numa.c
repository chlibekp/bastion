/* See numa.h. */
#include "ops/numa.h"

#include "core/log.h"

#include <dirent.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mimalloc.h> /* linked in every build: OpenSSL allocates from it (Makefile) */

static const bst_cfg_tuning dflt = { .affinity = BST_AFFINITY_NONE, .numa = true,
				     .huge_pages = BST_HUGE_OFF };

const bst_cfg_tuning *bst_tuning(const bst_config *cfg)
{
	return cfg->global.tuning != NULL ? cfg->global.tuning : &dflt;
}

size_t bst_cpus_allowed(int *out, size_t cap)
{
	cpu_set_t set;
	size_t n = 0;
	if (sched_getaffinity(0, sizeof set, &set) != 0) {
		long on = sysconf(_SC_NPROCESSORS_ONLN);
		for (long i = 0; i < on && n < cap; i++)
			out[n++] = (int)i;
		return n;
	}
	for (int i = 0; i < CPU_SETSIZE && n < cap; i++)
		if (CPU_ISSET((size_t)i, &set))
			out[n++] = i;
	return n;
}

static const char *sysfs_root(void)
{
#ifdef BST_TEST
	const char *r = getenv("BST_TEST_SYSFS"); /* a fake tree: NUMA layouts and THP modes */
	if (r != NULL)
		return r;
#endif
	return "/sys";
}

int bst_numa_node_of(int cpu)
{
	char path[512];
	snprintf(path, sizeof path, "%s/devices/system/cpu/cpu%d", sysfs_root(), cpu);
	DIR *d = opendir(path);
	if (d == NULL)
		return -1;
	int node = -1;
	struct dirent *e;
	while ((e = readdir(d)) != NULL)
		if (strncmp(e->d_name, "node", 4) == 0 && e->d_name[4] >= '0' && e->d_name[4] <= '9') {
			node = atoi(e->d_name + 4);
			break;
		}
	closedir(d);
	return node;
}

int bst_numa_nodes(void)
{
	char path[512];
	snprintf(path, sizeof path, "%s/devices/system/node", sysfs_root());
	DIR *d = opendir(path);
	if (d == NULL)
		return 1;
	int n = 0;
	struct dirent *e;
	while ((e = readdir(d)) != NULL)
		n += strncmp(e->d_name, "node", 4) == 0 && e->d_name[4] >= '0' && e->d_name[4] <= '9';
	closedir(d);
	return n > 0 ? n : 1;
}

static int map[BST_CPU_LIST_MAX];
static int nmap;

typedef struct cpu_node {
	int cpu, node;
} cpu_node;

static int cmp_node(const void *a, const void *b)
{
	const cpu_node *x = a, *y = b;
	if (x->node != y->node)
		return x->node < y->node ? -1 : 1;
	return x->cpu < y->cpu ? -1 : x->cpu > y->cpu;
}

bool bst_cpu_map_build(const bst_config *cfg, bool pin)
{
	const bst_cfg_tuning *t = bst_tuning(cfg);
	nmap = 0;
	if (t->affinity == BST_AFFINITY_LIST) {
		for (size_t i = 0; i < t->ncpus && i < BST_CPU_LIST_MAX; i++)
			map[nmap++] = t->cpus[i];
		return true;
	}
	if (t->affinity == BST_AFFINITY_NONE && !pin)
		return false;
	int cpus[BST_CPU_LIST_MAX];
	size_t n = bst_cpus_allowed(cpus, BST_CPU_LIST_MAX);
	if (n == 0)
		return false;
	int nodes = t->numa ? bst_numa_nodes() : 1;
	if (nodes > 1) { /* node by node, so neighbouring slots share memory */
		cpu_node cn[BST_CPU_LIST_MAX];
		for (size_t i = 0; i < n; i++)
			cn[i] = (cpu_node){ cpus[i], bst_numa_node_of(cpus[i]) };
		qsort(cn, n, sizeof cn[0], cmp_node);
		for (size_t i = 0; i < n; i++)
			cpus[i] = cn[i].cpu;
		bst_log(BST_LOG_INFO, "numa: %d nodes: workers fill the CPUs node by node", nodes);
	} else if (t->numa) {
		bst_log(BST_LOG_DEBUG, "numa: a single node: nothing to place");
	}
	for (size_t i = 0; i < n; i++)
		map[nmap++] = cpus[i];
	return true;
}

int bst_cpu_map_slot(int slot)
{
	return nmap > 0 && slot >= 0 ? map[slot % nmap] : -1;
}

int bst_cpu_map_len(void)
{
	return nmap;
}

const char *bst_thp_mode(char *buf, size_t cap)
{
	char path[512];
	snprintf(path, sizeof path, "%s/kernel/mm/transparent_hugepage/enabled", sysfs_root());
	FILE *f = fopen(path, "re");
	if (f == NULL)
		return NULL;
	char line[128];
	const char *r = NULL;
	if (fgets(line, sizeof line, f) != NULL) {
		char *o = strchr(line, '['), *c = o != NULL ? strchr(o, ']') : NULL;
		if (o != NULL && c != NULL && (size_t)(c - o) < cap) {
			memcpy(buf, o + 1, (size_t)(c - o - 1));
			buf[c - o - 1] = '\0';
			r = buf;
		}
	}
	fclose(f);
	return r;
}

void bst_huge_pages_apply(const bst_config *cfg)
{
	const bst_cfg_tuning *t = bst_tuning(cfg);
	if (t->huge_pages == BST_HUGE_OFF)
		return;
	char mode[32];
	const char *m = bst_thp_mode(mode, sizeof mode);
	if (m == NULL || strcmp(m, "never") == 0) {
		bst_log(t->huge_pages == BST_HUGE_ON ? BST_LOG_WARN : BST_LOG_INFO,
			"huge_pages: transparent huge pages are %s: using normal pages",
			m == NULL ? "not available" : "off (never)");
		return;
	}
	mi_option_enable(mi_option_allow_large_os_pages);
	bst_log(BST_LOG_INFO, "huge_pages: the allocator asks for transparent huge pages (%s)", m);
}

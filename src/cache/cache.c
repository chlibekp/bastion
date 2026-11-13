/* See cache.h. */
#include "cache/cache.h"

#include "cache/ram.h"
#include "core/log.h"
#include "core/shm.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* mkdir -p, then the ownership of the last component. */
static int make_root(const char *path, bool chown_dirs, uid_t uid, gid_t gid)
{
	char p[4096];
	snprintf(p, sizeof p, "%s", path);
	for (char *s = strchr(p + 1, '/'); s != NULL; s = strchr(s + 1, '/')) {
		*s = 0;
		if (mkdir(p, 0755) != 0 && errno != EEXIST)
			return -errno;
		*s = '/';
	}
	if (mkdir(p, 0700) != 0 && errno != EEXIST)
		return -errno;
	if (chown_dirs && chown(p, uid, gid) != 0)
		return -errno;
	return 0;
}

bst_ram *bst_cache_ram(bst_cache_rt *rt)
{
	if (rt->ram == NULL && rt->ram_each > 0)
		rt->ram = bst_ram_new((size_t)rt->ram_each, (size_t)rt->cfg->ram_max_object);
	return rt->ram;
}

int bst_cache_setup(bst_config *cfg, int nworkers, bool chown_dirs, uid_t uid, gid_t gid,
		    bst_err *e)
{
	bst_cfg_global *g = &cfg->global;
	for (size_t i = 0; i < g->ncache_stores; i++) {
		bst_cfg_cache_store *s = g->cache_stores[i];
		if (s->rt != NULL)
			continue;
		bst_cache_rt *rt = calloc(1, sizeof *rt);
		if (rt == NULL) {
			bst_err_set(e, "cache_store %s: out of memory", s->name);
			return -1;
		}
		rt->cfg = s;
		rt->ram_each = s->ram / (uint64_t)(nworkers > 0 ? nworkers : 1);
		s->rt = rt;
		int rc = make_root(s->path, chown_dirs, uid, gid);
		if (rc == 0) {
			s->dirfd = open(s->path, O_PATH | O_DIRECTORY | O_CLOEXEC);
			rc = s->dirfd < 0 ? -errno : 0;
		}
		if (rc != 0) {
			bst_log(BST_LOG_WARN, "cache_store %s: %s: %s: serving without this cache", s->name,
				s->path, strerror(-rc));
			rt->broken = true;
		}
		bst_store_init(&rt->store, s->dirfd);
		size_t isz = bst_cindex_size((size_t)s->max_entries);
		void *m = bst_shm_create("bastion-cache-index", isz, NULL);
		if (m == NULL) {
			bst_err_set(e, "cache_store %s: index shared memory (%zu bytes): %s", s->name, isz,
				    strerror(errno));
			return -1;
		}
		rt->idx = bst_cindex_init(m, (size_t)s->max_entries);
	}
	return 0;
}

size_t bst_cache_paths(const bst_config *cfg, const char **out, size_t max)
{
	size_t n = 0;
	for (size_t i = 0; i < cfg->global.ncache_stores && n < max; i++) {
		const bst_cfg_cache_store *s = cfg->global.cache_stores[i];
		const bst_cache_rt *rt = s->rt;
		if (rt == NULL || !rt->broken)
			out[n++] = s->path;
	}
	return n;
}

/* ---- the helper ---- */

typedef struct hjob {
	bst_loop *l;
	bst_cache_rt *rt;
	bst_timer scan_t, evict_t;
	bst_cache_scan sc;
	unsigned per_step;
	uint64_t scan_ms;
	size_t cursor;
	uint64_t rng;
} hjob;

static void on_evict(void *ud)
{
	hjob *j = ud;
	bst_cfg_cache_store *s = j->rt->cfg;
	bst_evict_cfg c = { .max_bytes = s->size, .inactive_s = (uint32_t)(s->inactive_ms / 1000),
			    .batch = s->evict_batch, .sample = 16 };
	unsigned n = bst_cache_evict(j->rt->idx, &j->rt->store, &c, (uint32_t)time(NULL), &j->cursor,
				     &j->rng);
	if (n > 0)
		bst_log(BST_LOG_DEBUG, "cache_store %s: evicted %u objects", s->name, n);
	uint64_t every = 1000;
#ifdef BST_TEST
	const char *t = getenv("BST_TEST_CACHE_EVICT_MS");
	if (t != NULL)
		every = strtoull(t, NULL, 10);
#endif
	bst_loop_timer_arm(j->l, &j->evict_t, every, on_evict, j);
}

static void on_scan(void *ud)
{
	hjob *j = ud;
	if (bst_cache_scan_step(j->rt->idx, &j->rt->store, &j->sc, j->per_step)) {
		bst_log(BST_LOG_INFO, "cache_store %s: index rebuilt: %llu files, %llu broken removed, "
				      "%llu leftover temp files removed",
			j->rt->cfg->name, (unsigned long long)j->sc.files, (unsigned long long)j->sc.bad,
			(unsigned long long)j->sc.tmp_removed);
		on_evict(j);
		return;
	}
	bst_loop_timer_arm(j->l, &j->scan_t, j->scan_ms, on_scan, j);
}

void bst_cache_helper_start(bst_loop *l, const bst_config *cfg)
{
	for (size_t i = 0; i < cfg->global.ncache_stores; i++) {
		bst_cache_rt *rt = cfg->global.cache_stores[i]->rt;
		if (rt == NULL || rt->broken)
			continue;
		hjob *j = calloc(1, sizeof *j);
		if (j == NULL)
			return;
		j->l = l;
		j->rt = rt;
		j->rng = (uint64_t)time(NULL) ^ (uint64_t)i;
		j->sc.started = (int64_t)time(NULL);
		j->scan_ms = 100;
		j->per_step = rt->cfg->scan_rate / 10 ? rt->cfg->scan_rate / 10 : 1;
#ifdef BST_TEST
		const char *slow = getenv("BST_TEST_CACHE_SCAN_DELAY_MS"); /* a slow disk */
		if (slow != NULL) {
			j->scan_ms = strtoull(slow, NULL, 10);
			j->per_step = 1;
		}
#endif
		bst_timer_init(&j->scan_t);
		bst_timer_init(&j->evict_t);
		bst_loop_timer_arm(l, &j->scan_t, 1, on_scan, j);
	}
}

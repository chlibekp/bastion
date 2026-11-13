/* The helper's jobs on a disk cache store (index.h): the startup scan that rebuilds the index
 * from the files, and eviction. Both run in the helper only, in bounded steps from its timers,
 * so the helper's loop stays responsive and workers serve traffic meanwhile (a file the scan
 * has not reached yet is a miss). Directories are read with getdents64 on a descriptor opened
 * beneath the root, the only way the sandbox allows. */
#include "cache/index.h"

#include "core/log.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct linux_dirent64 {
	uint64_t d_ino;
	int64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

static int open_dir(int dirfd, const char *rel)
{
	struct open_how how;
	memset(&how, 0, sizeof how);
	how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
	how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
	int fd = (int)syscall(SYS_openat2, dirfd, rel, &how, sizeof how);
	return fd < 0 ? -errno : fd;
}

/* Calls fn for each regular name in dir rel, up to max; returns how many it saw. */
static unsigned each_file(int dirfd, const char *rel, unsigned max,
			  void (*fn)(void *ud, const char *dir, const char *name), void *ud)
{
	int fd = open_dir(dirfd, rel);
	if (fd < 0)
		return 0;
	char buf[8192];
	unsigned n = 0;
	for (;;) {
		long got = syscall(SYS_getdents64, fd, buf, sizeof buf);
		if (got <= 0)
			break;
		for (long off = 0; off < got;) {
			struct linux_dirent64 *e = (struct linux_dirent64 *)(void *)(buf + off);
			off += e->d_reclen;
			if (e->d_name[0] == '.')
				continue;
			fn(ud, rel, e->d_name);
			n++;
		}
		if (n >= max)
			break;
	}
	close(fd);
	return n;
}

typedef struct scan_ctx {
	bst_cindex *x;
	bst_store *st;
	bst_cache_scan *sc;
	uint32_t now;
} scan_ctx;

static void scan_one(void *ud, const char *dir, const char *name)
{
	scan_ctx *c = ud;
	char rel[96];
	snprintf(rel, sizeof rel, "%s/%s", dir, name);
	bst_key k;
	bst_sobj_meta m;
	uint64_t disk = 0;
	c->sc->files++;
	int rc = bst_store_peek(c->st, rel, &k, &m, &disk);
	char want[71];
	if (rc == 0)
		bst_store_path(&k, want);
	if (rc != 0 || strcmp(want, rel) != 0) {
		c->sc->bad++;
		(void)unlinkat(c->st->dirfd, rel, 0); /* broken, or not where its key says */
		return;
	}
	bst_centry e;
	memset(&e, 0, sizeof e);
	bst_centry have;
	if (bst_cindex_lookup(c->x, &k, &have))
		return; /* a worker filled it again already: that one is newer */
	e.key = k;
	e.size = disk;
	e.stored_at_ms = m.stored_at_ms;
	e.req_time = m.req_time;
	e.resp_time = m.resp_time;
	e.last_access = c->now;
	(void)bst_cindex_insert(c->x, &e);
}

static void tmp_one(void *ud, const char *dir, const char *name)
{
	scan_ctx *c = ud;
	char rel[96];
	snprintf(rel, sizeof rel, "%s/%s", dir, name);
	struct statx sx; /* statx: the call the sandbox allows (fstatat is newfstatat, refused) */
	if (statx(c->st->dirfd, rel, AT_SYMLINK_NOFOLLOW, STATX_MTIME, &sx) == 0 &&
	    sx.stx_mtime.tv_sec < c->sc->started && unlinkat(c->st->dirfd, rel, 0) == 0)
		c->sc->tmp_removed++; /* a fill that died with its process */
}

bool bst_cache_scan_step(bst_cindex *x, bst_store *st, bst_cache_scan *sc, unsigned max)
{
	scan_ctx c = { x, st, sc, (uint32_t)time(NULL) };
	if (!sc->tmp_done) {
		(void)each_file(st->dirfd, "tmp", ~0u, tmp_one, &c);
		sc->tmp_done = true;
	}
	unsigned done = 0;
	while (sc->d1 < 256 && done < max) {
		char rel[8];
		snprintf(rel, sizeof rel, "%02x/%02x", sc->d1, sc->d2);
		done += each_file(st->dirfd, rel, max - done + 64, scan_one, &c);
		if (++sc->d2 == 256) {
			sc->d2 = 0;
			sc->d1++;
		}
	}
	if (sc->d1 < 256)
		return false;
	bst_cindex_set_scanned(x);
	return true;
}

static uint64_t next_rand(uint64_t *s)
{
	uint64_t z = (*s += 0x9e3779b97f4a7c15ull);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
	return z ^ (z >> 31);
}

static bool drop(bst_cindex *x, bst_store *st, const bst_centry *e)
{
	if (!bst_cindex_remove(x, &e->key))
		return false;
	(void)bst_store_delete(st, &e->key);
	return true;
}

unsigned bst_cache_evict(bst_cindex *x, bst_store *st, const bst_evict_cfg *c, uint32_t now,
			 size_t *cursor, uint64_t *rng)
{
	unsigned removed = 0, batch = c->batch ? c->batch : 64;
	size_t n = bst_cindex_nslots(x);
	if (n == 0)
		return 0;
	/* `inactive`: a slice of the table per call, so the whole table is swept over time */
	if (c->inactive_s > 0) {
		size_t span = n < 4096 ? n : 4096;
		for (size_t i = 0; i < span && removed < batch; i++) {
			size_t at = (*cursor + i) % n;
			bst_centry e;
			if (bst_cindex_slot(x, at, &e) && now > e.last_access &&
			    now - e.last_access > c->inactive_s && drop(x, st, &e))
				removed++;
		}
		*cursor = (*cursor + span) % n;
	}
	/* size: sampled LRU */
	unsigned sample = c->sample ? c->sample : 16;
	while (bst_cindex_bytes(x) > c->max_bytes && removed < batch && bst_cindex_count(x) > 0) {
		bst_centry best;
		bool have = false;
		size_t start = (size_t)(next_rand(rng) % n);
		unsigned seen = 0;
		for (size_t i = 0; i < n && seen < sample; i++) {
			bst_centry e;
			if (!bst_cindex_slot(x, (start + i) % n, &e))
				continue;
			seen++;
			if (!have || e.last_access < best.last_access) {
				best = e;
				have = true;
			}
		}
		if (!have)
			break;
		if (drop(x, st, &best))
			removed++;
	}
	return removed;
}

/* See purge.h. */
#include "cache/purge.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAGIC 0x6273747075726731ull /* "bstpurg1" */

struct bst_purge_table {
	uint64_t nslots;
	_Atomic uint64_t gen; /* bumped by every purge: the helper saves when it moved */
	_Atomic int64_t all;  /* store-wide */
	_Alignas(64) _Atomic int64_t at[];
};

size_t bst_purge_size(size_t nslots)
{
	return sizeof(bst_purge_table) + nslots * sizeof(_Atomic int64_t);
}

bst_purge_table *bst_purge_init(void *mem, size_t nslots)
{
	bst_purge_table *t = mem;
	t->nslots = nslots;
	return t;
}

static uint64_t hash_ns(const char *ns, bst_str v, bool fold)
{
	char buf[512];
	size_t n = strlen(ns);
	memcpy(buf, ns, n);
	for (uint32_t i = 0; i < v.len && n < sizeof buf; i++) {
		char c = v.p[i];
		buf[n++] = fold && c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
	}
	bst_key k;
	bst_key_make((bst_str){ buf, (uint32_t)n }, &k);
	return bst_key_u64(&k);
}

uint64_t bst_purge_hash_tag(bst_str tag)
{
	return hash_ns("tag\n", tag, false);
}

uint64_t bst_purge_hash_host(bst_str host)
{
	if (host.len > 0 && host.p[0] != '[') {
		const char *c = memchr(host.p, ':', host.len);
		if (c != NULL)
			host.len = (uint32_t)(c - host.p);
	}
	return hash_ns("host\n", host, true);
}

uint64_t bst_purge_hash_url(const bst_key *k)
{
	return bst_key_u64(k) ^ 0x75726c75726c7572ull; /* apart from tags and hosts */
}

static void bump(_Atomic int64_t *slot, int64_t when)
{
	int64_t cur = atomic_load_explicit(slot, memory_order_relaxed);
	while (cur < when && !atomic_compare_exchange_weak_explicit(slot, &cur, when,
								    memory_order_release,
								    memory_order_relaxed))
		;
}

void bst_purge_mark(bst_purge_table *t, uint64_t h, int64_t when_ms)
{
	if (t != NULL && t->nslots > 0) {
		bump(&t->at[h % t->nslots], when_ms);
		atomic_fetch_add_explicit(&t->gen, 1, memory_order_relaxed);
	}
}

void bst_purge_mark_all(bst_purge_table *t, int64_t when_ms)
{
	if (t != NULL) {
		bump(&t->all, when_ms);
		atomic_fetch_add_explicit(&t->gen, 1, memory_order_relaxed);
	}
}

uint64_t bst_purge_gen(const bst_purge_table *t)
{
	return atomic_load_explicit(&((bst_purge_table *)t)->gen, memory_order_relaxed);
}

static int64_t at(const bst_purge_table *t, uint64_t h)
{
	return atomic_load_explicit(&((bst_purge_table *)t)->at[h % t->nslots], memory_order_acquire);
}

bool bst_purge_valid(const bst_purge_table *t, int64_t stored_at_ms, const bst_key *key,
		     const bst_key *base, uint64_t host_hash, const uint64_t *tags, uint32_t ntags)
{
	if (t == NULL || t->nslots == 0)
		return true;
	if (stored_at_ms <= atomic_load_explicit(&((bst_purge_table *)t)->all, memory_order_acquire))
		return false;
	if (key != NULL && stored_at_ms <= at(t, bst_purge_hash_url(key)))
		return false;
	if (base != NULL && stored_at_ms <= at(t, bst_purge_hash_url(base)))
		return false;
	if (host_hash != 0 && stored_at_ms <= at(t, host_hash))
		return false;
	for (uint32_t i = 0; i < ntags; i++)
		if (stored_at_ms <= at(t, tags[i]))
			return false;
	return true;
}

uint32_t bst_purge_tags(bst_str v, uint64_t *out, uint32_t max)
{
	uint32_t n = 0, i = 0;
	while (i < v.len && n < max) {
		while (i < v.len && (v.p[i] == ',' || v.p[i] == ' ' || v.p[i] == '\t'))
			i++;
		uint32_t s = i;
		while (i < v.len && v.p[i] != ',' && v.p[i] != ' ' && v.p[i] != '\t')
			i++;
		if (i > s)
			out[n++] = bst_purge_hash_tag((bst_str){ v.p + s, i - s });
	}
	return n;
}

static int open_beneath(int dirfd, const char *rel, int flags)
{
	struct open_how how;
	memset(&how, 0, sizeof how);
	how.flags = (uint64_t)(flags | O_CLOEXEC);
	how.mode = (flags & O_CREAT) ? 0600 : 0;
	how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
	int fd = (int)syscall(SYS_openat2, dirfd, rel, &how, sizeof how);
	return fd < 0 ? -errno : fd;
}

int bst_purge_save(const bst_purge_table *t, int dirfd)
{
	size_t n = (size_t)t->nslots, sz = 3 * sizeof(int64_t) + n * sizeof(int64_t);
	int64_t *b = malloc(sz);
	if (b == NULL)
		return -ENOMEM;
	b[0] = (int64_t)MAGIC;
	b[1] = (int64_t)n;
	b[2] = atomic_load(&((bst_purge_table *)t)->all);
	for (size_t i = 0; i < n; i++)
		b[3 + i] = atomic_load_explicit(&((bst_purge_table *)t)->at[i], memory_order_relaxed);
	int fd = open_beneath(dirfd, "purge.table.tmp", O_WRONLY | O_CREAT | O_TRUNC);
	int rc = fd < 0 ? fd : 0;
	size_t done = 0;
	while (rc == 0 && done < sz) {
		ssize_t w = pwrite(fd, (char *)b + done, sz - done, (off_t)done);
		if (w < 0 && errno == EINTR)
			continue;
		rc = w <= 0 ? -EIO : 0;
		done += w > 0 ? (size_t)w : 0;
	}
	if (fd >= 0)
		close(fd);
	free(b);
	if (rc == 0 && syscall(SYS_renameat2, dirfd, "purge.table.tmp", dirfd, "purge.table", 0) != 0)
		rc = -errno;
	return rc;
}

int bst_purge_load(bst_purge_table *t, int dirfd)
{
	int fd = open_beneath(dirfd, "purge.table", O_RDONLY);
	if (fd == -ENOENT)
		return 0;
	if (fd < 0)
		return fd;
	struct stat sb;
	int rc = fstat(fd, &sb) != 0 ? -errno : 0;
	int64_t hdr[3];
	if (rc == 0 && (sb.st_size < (off_t)sizeof hdr || pread(fd, hdr, sizeof hdr, 0) != (ssize_t)sizeof hdr ||
			hdr[0] != (int64_t)MAGIC || hdr[1] < 0 ||
			sb.st_size != (off_t)(sizeof hdr + (size_t)hdr[1] * sizeof(int64_t))))
		rc = -EBADMSG;
	if (rc == 0) {
		size_t n = (size_t)hdr[1];
		int64_t *b = malloc(n * sizeof *b + 1);
		if (b == NULL || pread(fd, b, n * sizeof *b, sizeof hdr) != (ssize_t)(n * sizeof *b)) {
			rc = b == NULL ? -ENOMEM : -EIO;
		} else {
			bump(&t->all, hdr[2]);
			int64_t newest = 0;
			for (size_t i = 0; i < n; i++) {
				if (n == t->nslots)
					bump(&t->at[i], b[i]);
				newest = b[i] > newest ? b[i] : newest;
			}
			if (n != t->nslots) /* another size: every saved purge covers everything */
				bump(&t->all, newest);
		}
		free(b);
	}
	close(fd);
	return rc;
}

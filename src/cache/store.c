/* See store.h. */
#include "cache/store.h"

#include "core/arena.h"
#include "http/headers.h"
#include "io/aio.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef struct disk_hdr {
	char magic[8];
	uint32_t version;
	uint32_t hdr_len; /* this struct plus the blobs */
	uint8_t key[32];
	int64_t stored_at_ms, req_time, resp_time;
	int32_t status;
	uint32_t head_len, vary_len, ntags;
	uint64_t host_hash;
	uint64_t body_off, body_len;
	uint8_t hash[32]; /* SHA-256 of this struct (hash zeroed) and the blobs */
} disk_hdr;

#define HDR_MAX (1u << 20) /* larger headers are refused */

void bst_key_make(bst_str s, bst_key *k)
{
	unsigned int n = 0;
	if (EVP_Digest(s.p, s.len, k->b, &n, EVP_sha256(), NULL) != 1 || n != 32)
		memset(k->b, 0, sizeof k->b); /* never: SHA-256 can not fail on memory */
}

void bst_key_hex(const bst_key *k, char out[65])
{
	static const char hx[] = "0123456789abcdef";
	for (int i = 0; i < 32; i++) {
		out[2 * i] = hx[k->b[i] >> 4];
		out[2 * i + 1] = hx[k->b[i] & 15];
	}
	out[64] = 0;
}

uint64_t bst_key_u64(const bst_key *k)
{
	uint64_t v;
	memcpy(&v, k->b, sizeof v);
	return v;
}

void bst_store_path(const bst_key *k, char out[71])
{
	char hx[65];
	bst_key_hex(k, hx);
	snprintf(out, 71, "%.2s/%.2s/%s", hx, hx + 2, hx);
}

void bst_store_init(bst_store *st, int dirfd)
{
	memset(st, 0, sizeof *st);
	st->dirfd = dirfd;
}

static int open_beneath(int dirfd, const char *rel, int flags, mode_t mode)
{
	struct open_how how;
	memset(&how, 0, sizeof how);
	how.flags = (uint64_t)(flags | O_CLOEXEC);
	how.mode = (flags & O_CREAT) ? mode : 0;
	how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
	int fd = (int)syscall(SYS_openat2, dirfd, rel, &how, sizeof how);
	return fd < 0 ? -errno : fd;
}

/* Makes the parent directories of rel ("ab/cd/x" or "tmp/x"). */
static void make_dirs(int dirfd, const char *rel)
{
	char p[80];
	snprintf(p, sizeof p, "%s", rel);
	for (char *s = strchr(p, '/'); s != NULL; s = strchr(s + 1, '/')) {
		*s = 0;
		if (mkdirat(dirfd, p, 0700) != 0 && errno != EEXIST)
			return;
		*s = '/';
	}
}

static void hdr_hash(const disk_hdr *h, const char *blobs, size_t bl, uint8_t out[32])
{
	disk_hdr c = *h;
	memset(c.hash, 0, sizeof c.hash);
	EVP_MD_CTX *x = EVP_MD_CTX_new();
	unsigned int n = 0;
	if (x == NULL || EVP_DigestInit_ex(x, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(x, &c, sizeof c) != 1 || (bl > 0 && EVP_DigestUpdate(x, blobs, bl) != 1) ||
	    EVP_DigestFinal_ex(x, out, &n) != 1)
		memset(out, 0xff, 32); /* never matches a real hash */
	EVP_MD_CTX_free(x);
}

static int pread_all(int fd, void *b, size_t n, off_t off)
{
	size_t got = 0;
	while (got < n) {
		ssize_t r = pread(fd, (char *)b + got, n - got, off + (off_t)got);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			return -errno;
		if (r == 0)
			return -EBADMSG; /* short file */
		got += (size_t)r;
	}
	return 0;
}

/* Reads and checks the header of fd: 0, -EBADMSG for a broken one. blob: malloc'd blobs. */
static int read_hdr(int fd, disk_hdr *h, char **blob, uint64_t *fsize)
{
	struct stat sb;
	if (fstat(fd, &sb) != 0)
		return -errno;
	*fsize = (uint64_t)sb.st_size;
	int rc = pread_all(fd, h, sizeof *h, 0);
	if (rc != 0)
		return rc;
	if (memcmp(h->magic, BST_STORE_MAGIC, 8) != 0 || h->version != BST_STORE_VERSION)
		return -EBADMSG; /* an old format is a miss, safely */
	uint64_t bl = (uint64_t)h->head_len + h->vary_len + (uint64_t)h->ntags * 8;
	if (h->ntags > BST_STORE_MAX_TAGS || bl > HDR_MAX || h->hdr_len != sizeof *h + bl ||
	    h->body_off < h->hdr_len || h->body_off % BST_STORE_PAGE != 0 ||
	    h->body_off + h->body_len != *fsize)
		return -EBADMSG; /* a body shorter (or longer) than declared too */
	char *b = malloc(bl + 1);
	if (b == NULL)
		return -ENOMEM;
	rc = pread_all(fd, b, bl, (off_t)sizeof *h);
	uint8_t hs[32];
	if (rc == 0) {
		hdr_hash(h, b, bl, hs);
		if (memcmp(hs, h->hash, 32) != 0)
			rc = -EBADMSG;
	}
	if (rc != 0) {
		free(b);
		return rc;
	}
	b[bl] = 0;
	*blob = b;
	return 0;
}

static void fill_meta(const disk_hdr *h, char *blob, bst_sobj_meta *m, uint64_t *tagbuf)
{
	m->stored_at_ms = h->stored_at_ms;
	m->req_time = h->req_time;
	m->resp_time = h->resp_time;
	m->status = h->status;
	m->body_len = h->body_len;
	m->host_hash = h->host_hash;
	m->ntags = h->ntags;
	if (blob != NULL) {
		m->head = (bst_str){ blob, h->head_len };
		m->vary = (bst_str){ blob + h->head_len, h->vary_len };
		if (tagbuf != NULL)
			memcpy(tagbuf, blob + h->head_len + h->vary_len, (size_t)h->ntags * 8);
		m->tags = tagbuf;
	}
}

int bst_store_read_sync(bst_store *st, const bst_key *k, bst_sobj **out)
{
	char rel[71];
	bst_store_path(k, rel);
	int fd = open_beneath(st->dirfd, rel, O_RDONLY, 0);
	if (fd < 0)
		return fd == -ENOTDIR ? -ENOENT : fd;
	bst_sobj *o = calloc(1, sizeof *o);
	if (o == NULL) {
		close(fd);
		return -ENOMEM;
	}
	disk_hdr h;
	uint64_t fsize;
	int rc = read_hdr(fd, &h, &o->blob, &fsize);
	if (rc == 0 && memcmp(h.key, k->b, 32) != 0)
		rc = -EBADMSG; /* another key's file: a miss */
	if (rc != 0) {
		close(fd);
		free(o->blob);
		free(o);
		if (rc == -EBADMSG) {
			atomic_fetch_add(&st->corrupt, 1);
			(void)unlinkat(st->dirfd, rel, 0);
		}
		return rc;
	}
	o->fd = fd;
	o->key = *k;
	o->body_off = h.body_off;
	fill_meta(&h, o->blob, &o->m, o->tagbuf);
	*out = o;
	return 0;
}

typedef struct read_job {
	bst_store *st;
	bst_key k;
	bst_sobj *o;
	int rc;
	bst_store_read_cb cb;
	void *ud;
} read_job;

static void read_work(void *arg)
{
	read_job *j = arg;
	j->rc = bst_store_read_sync(j->st, &j->k, &j->o);
}

static void read_done(void *arg)
{
	read_job *j = arg;
	j->cb(j->ud, j->rc == 0 ? j->o : NULL, j->rc);
	free(j);
}

int bst_store_open_read(bst_store *st, bst_loop *l, const bst_key *k, bst_store_read_cb cb, void *ud)
{
	read_job *j = calloc(1, sizeof *j);
	if (j == NULL)
		return -ENOMEM;
	j->st = st;
	j->k = *k;
	j->cb = cb;
	j->ud = ud;
	int rc = bst_aio_submit(l, read_work, read_done, j);
	if (rc != 0)
		free(j);
	return rc;
}

void bst_sobj_free(bst_sobj *o)
{
	if (o == NULL)
		return;
	if (o->fd >= 0)
		close(o->fd);
	free(o->blob);
	free(o);
}

int bst_sobj_headers(const bst_sobj *o, bst_headers *out, bst_arena *a)
{
	bst_headers_init(out, a);
	const char *p = o->m.head.p, *end = p + o->m.head.len;
	while (p < end) {
		const char *nz = memchr(p, 0, (size_t)(end - p));
		if (nz == NULL)
			return -1;
		const char *v = nz + 1;
		const char *vz = v < end ? memchr(v, 0, (size_t)(end - v)) : NULL;
		if (vz == NULL)
			return -1;
		if (bst_headers_add(out, (bst_str){ p, (uint32_t)(nz - p) },
				    (bst_str){ v, (uint32_t)(vz - v) }) != 0)
			return -1;
		p = vz + 1;
	}
	return 0;
}

/* ---- writing ---- */

struct bst_swriter {
	bst_store *st;
	int fd;
	char tmp[96];
	bst_key k;
	disk_hdr h;
	char *blobs;
	size_t bl;
	uint64_t written;
};

bst_swriter *bst_store_begin_write(bst_store *st, const bst_key *k, const bst_sobj_meta *m)
{
	if (m->ntags > BST_STORE_MAX_TAGS) {
		errno = EINVAL;
		return NULL;
	}
	size_t bl = (size_t)m->head.len + m->vary.len + (size_t)m->ntags * 8;
	if (bl > HDR_MAX) {
		errno = E2BIG;
		return NULL;
	}
	bst_swriter *w = calloc(1, sizeof *w);
	char *b = malloc(bl + 1);
	if (w == NULL || b == NULL) {
		free(w);
		free(b);
		errno = ENOMEM;
		return NULL;
	}
	if (m->head.len > 0)
		memcpy(b, m->head.p, m->head.len);
	if (m->vary.len > 0)
		memcpy(b + m->head.len, m->vary.p, m->vary.len);
	if (m->ntags > 0)
		memcpy(b + m->head.len + m->vary.len, m->tags, (size_t)m->ntags * 8);
	w->st = st;
	w->k = *k;
	w->blobs = b;
	w->bl = bl;
	char hx[65];
	bst_key_hex(k, hx);
	snprintf(w->tmp, sizeof w->tmp, "tmp/%s.%d.%llu", hx, (int)getpid(),
		 (unsigned long long)++st->seq);
	int fd = open_beneath(st->dirfd, w->tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd == -ENOENT) {
		make_dirs(st->dirfd, w->tmp);
		fd = open_beneath(st->dirfd, w->tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	}
	if (fd < 0) {
		atomic_fetch_add(&st->write_errors, 1);
		free(b);
		free(w);
		errno = -fd;
		return NULL;
	}
	w->fd = fd;
	disk_hdr *h = &w->h;
	memcpy(h->magic, BST_STORE_MAGIC, 8);
	h->version = BST_STORE_VERSION;
	h->hdr_len = (uint32_t)(sizeof *h + bl);
	memcpy(h->key, k->b, 32);
	h->stored_at_ms = m->stored_at_ms;
	h->req_time = m->req_time;
	h->resp_time = m->resp_time;
	h->status = m->status;
	h->head_len = m->head.len;
	h->vary_len = m->vary.len;
	h->ntags = m->ntags;
	h->host_hash = m->host_hash;
	h->body_off = (h->hdr_len + BST_STORE_PAGE - 1) / BST_STORE_PAGE * BST_STORE_PAGE;
	return w;
}

static int pwrite_all(int fd, const void *p, size_t n, off_t off)
{
	size_t done = 0;
	while (done < n) {
		ssize_t r = pwrite(fd, (const char *)p + done, n - done, off + (off_t)done);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			return -errno;
		if (r == 0)
			return -EIO;
		done += (size_t)r;
	}
	return 0;
}

int bst_store_write(bst_swriter *w, const void *p, size_t n)
{
#ifdef BST_TEST
	if (w->st->test_space > 0 && w->written + n > (uint64_t)w->st->test_space)
		return -ENOSPC;
	if (getenv("BST_TEST_CACHE_ENOSPC") != NULL)
		return -ENOSPC; /* a full disk, without filling one */
#endif
	int rc = pwrite_all(w->fd, p, n, (off_t)(w->h.body_off + w->written));
	if (rc == 0)
		w->written += n;
	return rc;
}

uint64_t bst_swriter_size(const bst_swriter *w)
{
	return w->written;
}

static void writer_free(bst_swriter *w, bool unlink_tmp)
{
	if (w->fd >= 0)
		close(w->fd);
	if (unlink_tmp)
		(void)unlinkat(w->st->dirfd, w->tmp, 0);
	free(w->blobs);
	free(w);
}

int bst_store_commit(bst_swriter *w)
{
	disk_hdr *h = &w->h;
	h->body_len = w->written;
	hdr_hash(h, w->blobs, w->bl, h->hash);
	int rc = pwrite_all(w->fd, h, sizeof *h, 0);
	if (rc == 0 && w->bl > 0)
		rc = pwrite_all(w->fd, w->blobs, w->bl, (off_t)sizeof *h);
	if (rc == 0 && w->written == 0 && ftruncate(w->fd, (off_t)h->body_off) != 0)
		rc = -errno; /* an empty body still ends at body_off */
	char rel[71];
	bst_store_path(&w->k, rel);
	if (rc == 0) {
		rc = (int)syscall(SYS_renameat2, w->st->dirfd, w->tmp, w->st->dirfd, rel, 0);
		if (rc != 0 && errno == ENOENT) {
			make_dirs(w->st->dirfd, rel);
			rc = (int)syscall(SYS_renameat2, w->st->dirfd, w->tmp, w->st->dirfd, rel, 0);
		}
		rc = rc != 0 ? -errno : 0;
	}
	if (rc != 0)
		atomic_fetch_add(&w->st->write_errors, 1);
	writer_free(w, rc != 0);
	return rc;
}

void bst_store_abort(bst_swriter *w)
{
	if (w != NULL)
		writer_free(w, true);
}

int bst_store_delete(bst_store *st, const bst_key *k)
{
	char rel[71];
	bst_store_path(k, rel);
	return unlinkat(st->dirfd, rel, 0) == 0 ? 0 : -errno;
}

int bst_store_peek(bst_store *st, const char *rel, bst_key *k, bst_sobj_meta *m, uint64_t *disk)
{
	int fd = open_beneath(st->dirfd, rel, O_RDONLY, 0);
	if (fd < 0)
		return fd;
	disk_hdr h;
	char *blob = NULL;
	uint64_t fsize = 0;
	int rc = read_hdr(fd, &h, &blob, &fsize);
	close(fd);
	if (rc != 0)
		return rc;
	memcpy(k->b, h.key, 32);
	memset(m, 0, sizeof *m);
	fill_meta(&h, NULL, m, NULL);
	*disk = fsize;
	free(blob);
	return 0;
}

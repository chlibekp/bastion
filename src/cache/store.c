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
#include <time.h>
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

/* The writer without its file: memory only, so it runs on the loop thread (st->seq is not
 * shared with the pool). writer_open makes the file; it may run on the pool. */
static bst_swriter *writer_new(bst_store *st, const bst_key *k, const bst_sobj_meta *m)
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
	w->fd = -1;
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

/* The temp file. 0, or a negative errno (counted). */
static int writer_open(bst_swriter *w)
{
	int fd = open_beneath(w->st->dirfd, w->tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd == -ENOENT) {
		make_dirs(w->st->dirfd, w->tmp);
		fd = open_beneath(w->st->dirfd, w->tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
	}
	if (fd < 0) {
		atomic_fetch_add(&w->st->write_errors, 1);
		return fd;
	}
	w->fd = fd;
	return 0;
}

static void writer_free(bst_swriter *w, bool unlink_tmp);

bst_swriter *bst_store_begin_write(bst_store *st, const bst_key *k, const bst_sobj_meta *m)
{
	bst_swriter *w = writer_new(st, k, m);
	if (w == NULL)
		return NULL;
	int rc = writer_open(w);
	if (rc != 0) {
		writer_free(w, false);
		errno = -rc;
		return NULL;
	}
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
	const char *slow = getenv("BST_TEST_CACHE_WRITE_DELAY_MS"); /* a slow disk */
	if (slow != NULL) { /* spins on the vDSO clock: the sandbox allows no sleep syscall */
		struct timespec t0, t;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		long ms = strtol(slow, NULL, 10);
		do
			clock_gettime(CLOCK_MONOTONIC, &t);
		while ((t.tv_sec - t0.tv_sec) * 1000L + (t.tv_nsec - t0.tv_nsec) / 1000000L < ms);
	}
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
	if (unlink_tmp && w->fd >= 0)
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

/* ---- writing on the aio pool (NFR5) ----
 *
 * The loop thread queues copies of the body; one job at a time per writer takes the queue to
 * the pool, which opens the temp file on the first job, appends in order, and commits or
 * removes it. While a job runs only the pool touches w and inflight; bst_aio_submit and the
 * done callback order those accesses. */

#define RETRY_MS 1 /* the pool's queue was full: try again on the next tick */

typedef struct achunk {
	struct achunk *next;
	size_t n;
	unsigned char d[];
} achunk;

struct bst_sawriter {
	bst_loop *loop;
	bst_swriter *w;	     /* NULL once committed or removed */
	achunk *q, **qtail;  /* accepted, not yet on the pool */
	achunk *inflight;    /* on the pool, in order */
	uint64_t queued;     /* bytes in q and inflight */
	uint64_t accepted;
	uint64_t queue_max;
	bool opened, busy;
	bool commit_req, aborted;
	bool job_commit, job_abort;
	int job_rc;
	int err; /* the first failure, sticky */
	bst_store_commit_cb cb;
	void *ud;
	bst_timer retry;
};

static void chunks_free(achunk *c)
{
	while (c != NULL) {
		achunk *n = c->next;
		free(c);
		c = n;
	}
}

static void aw_work(void *arg)
{
	bst_sawriter *a = arg;
	a->job_rc = 0;
	if (a->job_abort) {
		writer_free(a->w, a->opened);
		a->w = NULL;
		return;
	}
	if (!a->opened) {
		int rc = writer_open(a->w);
		if (rc != 0) {
			a->job_rc = rc;
			return;
		}
		a->opened = true;
	}
	for (achunk *c = a->inflight; c != NULL; c = c->next) {
		int rc = bst_store_write(a->w, c->d, c->n);
		if (rc != 0) {
			atomic_fetch_add(&a->w->st->write_errors, 1);
			a->job_rc = rc;
			return;
		}
	}
	if (a->job_commit) {
		a->job_rc = bst_store_commit(a->w); /* frees w either way */
		a->w = NULL;
	}
}

static void aw_kick(bst_sawriter *a);

static void aw_free(bst_sawriter *a)
{
	bst_timer_cancel(&a->retry);
	chunks_free(a->q);
	chunks_free(a->inflight);
	free(a);
}

static void aw_done(void *arg)
{
	bst_sawriter *a = arg;
	a->busy = false;
	for (achunk *c = a->inflight; c != NULL; c = c->next)
		a->queued -= c->n;
	chunks_free(a->inflight);
	a->inflight = NULL;
	if (a->job_rc != 0 && a->err == 0)
		a->err = a->job_rc;
	if (a->w == NULL) { /* committed, or removed */
		if (!a->aborted && a->cb != NULL)
			a->cb(a->ud, a->err);
		aw_free(a);
		return;
	}
	aw_kick(a);
}

static void aw_retry(void *ud)
{
	aw_kick(ud);
}

static void aw_kick(bst_sawriter *a)
{
	if (a->busy)
		return;
	a->job_commit = a->job_abort = false;
	if (a->aborted || a->err != 0) {
		if (!a->aborted && !a->commit_req)
			return; /* failed: removed when the caller commits or aborts */
		a->job_abort = true;
		chunks_free(a->q);
		a->q = NULL;
		a->qtail = &a->q;
		a->queued = 0;
	} else if (a->q != NULL) {
		a->inflight = a->q;
		a->q = NULL;
		a->qtail = &a->q;
		a->job_commit = a->commit_req; /* the last bytes and the commit in one job */
	} else if (a->commit_req) {
		a->job_commit = true;
	} else {
		return;
	}
	a->busy = true;
	int rc = bst_aio_submit(a->loop, aw_work, aw_done, a);
	if (rc == 0)
		return;
	if (rc == -ESHUTDOWN) { /* the loop is going away: nothing else runs on it */
		aw_work(a);
		aw_done(a);
		return;
	}
	a->busy = false; /* -EAGAIN: the pool is full; nothing was lost */
	if (a->inflight != NULL) {
		achunk **t = &a->inflight;
		while (*t != NULL)
			t = &(*t)->next;
		*t = a->q;
		if (a->q == NULL)
			a->qtail = t;
		a->q = a->inflight;
		a->inflight = NULL;
	}
	bst_loop_timer_arm(a->loop, &a->retry, RETRY_MS, aw_retry, a);
}

bst_sawriter *bst_store_async_begin(bst_store *st, bst_loop *l, const bst_key *k,
				    const bst_sobj_meta *m, uint64_t queue_max)
{
	bst_sawriter *a = calloc(1, sizeof *a);
	if (a == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	a->w = writer_new(st, k, m);
	if (a->w == NULL) {
		free(a);
		return NULL;
	}
	a->loop = l;
	a->qtail = &a->q;
	a->queue_max = queue_max;
	bst_timer_init(&a->retry);
	return a;
}

int bst_store_async_write(bst_sawriter *a, const void *p, size_t n)
{
	if (a->err != 0)
		return a->err;
	if (n == 0)
		return 0;
	if (a->queued + n > a->queue_max)
		return -ENOBUFS; /* the disk is behind by more than write_queue_max */
	achunk *c = malloc(sizeof *c + n);
	if (c == NULL)
		return -ENOMEM;
	c->next = NULL;
	c->n = n;
	memcpy(c->d, p, n);
	*a->qtail = c;
	a->qtail = &c->next;
	a->queued += n;
	a->accepted += n;
	aw_kick(a);
	return 0;
}

uint64_t bst_sawriter_size(const bst_sawriter *a)
{
	return a->accepted;
}

uint64_t bst_sawriter_queued(const bst_sawriter *a)
{
	return a->queued;
}

void bst_store_async_commit(bst_sawriter *a, bst_store_commit_cb cb, void *ud)
{
	a->commit_req = true;
	a->cb = cb;
	a->ud = ud;
	aw_kick(a);
}

void bst_store_async_abort(bst_sawriter *a)
{
	if (a == NULL)
		return;
	a->aborted = true;
	a->cb = NULL;
	aw_kick(a); /* when busy, aw_done removes it after the job */
}

typedef struct del_job {
	bst_store *st;
	bst_loop *loop;
	bst_key k;
	bst_timer retry;
} del_job;

static void del_work(void *arg)
{
	del_job *j = arg;
	(void)bst_store_delete(j->st, &j->k);
}

static void del_done(void *arg)
{
	del_job *j = arg;
	bst_timer_cancel(&j->retry);
	free(j);
}

static void del_submit(void *arg)
{
	del_job *j = arg;
	int rc = bst_aio_submit(j->loop, del_work, del_done, j);
	if (rc == -EAGAIN) {
		bst_loop_timer_arm(j->loop, &j->retry, RETRY_MS, del_submit, j);
	} else if (rc != 0) { /* the loop is going away */
		del_work(j);
		del_done(j);
	}
}

int bst_store_async_delete(bst_store *st, bst_loop *l, const bst_key *k)
{
	del_job *j = calloc(1, sizeof *j);
	if (j == NULL)
		return -ENOMEM;
	j->st = st;
	j->loop = l;
	j->k = *k;
	bst_timer_init(&j->retry);
	del_submit(j);
	return 0;
}

/* See spool.h. */
#include "proxy/spool.h"

#include "config/compile.h"
#include "core/log.h"
#include "io/aio.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#ifndef O_TMPFILE
#define O_TMPFILE (020000000 | O_DIRECTORY)
#endif

#define RETRY_MS 1 /* the aio queue was full: try again on the next tick */

/* Bytes accepted for the file, waiting for the pool to write them. */
typedef struct wchunk {
	struct wchunk *next;
	size_t n;
	unsigned char d[];
} wchunk;

struct bst_spool {
	bst_loop *loop;
	int dir_fd; /* temp_path (borrowed from the config), -1 when there is none */
	int fd;	    /* the temp file, -1 until the first write job opens it */
	uint64_t limit;
	unsigned char *mem;
	size_t mlen, mcap;
	uint64_t flen; /* bytes written to the file */
	/* write-behind: bytes at file offsets flen.. in order, q after inflight */
	wchunk *inflight; /* on the pool */
	wchunk *q, **qtail;
	uint64_t qlen;	  /* bytes in inflight and q */
	uint64_t wdone;	  /* the job: bytes of inflight it wrote */
	int wrc;	  /* the job: its outcome */
	int werr;	  /* the first write failure, sticky */
	bool writing;
	bst_timer retry;
	bst_spool_flush_cb fcb;
	void *fud;
	/* the one read on the aio pool */
	bool reading, closing;
	bst_buf *rb;
	uint64_t roff;
	int rerr;
	bst_spool_read_cb cb;
	void *ud;
};

bst_spool *bst_spool_open(bst_worker *w, uint64_t limit)
{
	bst_spool *sp = calloc(1, sizeof *sp);
	if (sp == NULL)
		return NULL;
	sp->loop = bst_worker_loop(w);
	const bst_config *cfg = bst_worker_config(w);
	sp->dir_fd = cfg != NULL ? cfg->global.temp_fd : -1;
	sp->fd = -1;
	sp->limit = limit;
	sp->qtail = &sp->q;
	bst_timer_init(&sp->retry);
	return sp;
}

uint64_t bst_spool_size(const bst_spool *sp)
{
	return sp->mlen + sp->flen + sp->qlen;
}

uint64_t bst_spool_spilled(const bst_spool *sp)
{
	return sp->flen + sp->qlen;
}

uint64_t bst_spool_pending(const bst_spool *sp)
{
	return sp->qlen;
}

static void chunks_free(wchunk *c)
{
	while (c != NULL) {
		wchunk *n = c->next;
		free(c);
		c = n;
	}
}

static void spool_free(bst_spool *sp)
{
	bst_timer_cancel(&sp->retry);
	chunks_free(sp->inflight);
	chunks_free(sp->q);
	if (sp->fd >= 0)
		close(sp->fd);
	free(sp->mem);
	free(sp);
}

/* ---- writing, on the aio pool ---- */

/* The unnamed file: never linked, so it goes when its descriptor does. Pool thread. */
static int open_tmp(bst_spool *sp)
{
	struct open_how how;
	memset(&how, 0, sizeof how);
	how.flags = O_TMPFILE | O_RDWR | O_CLOEXEC;
	how.mode = 0600;
	how.resolve = RESOLVE_BENEATH;
	int fd = (int)syscall(SYS_openat2, sp->dir_fd, ".", &how, sizeof how);
	if (fd < 0)
		return -errno;
	sp->fd = fd;
	return 0;
}

/* Pool thread: appends inflight at flen. Only this job touches fd, inflight, wdone and wrc
 * until write_done; flen is not changed meanwhile. */
static void write_work(void *arg)
{
	bst_spool *sp = arg;
	sp->wdone = 0;
	sp->wrc = 0;
#ifdef BST_TEST
	if (getenv("BST_TEST_SPOOL_ENOSPC") != NULL) {
		sp->wrc = -ENOSPC; /* a full disk, without filling one */
		return;
	}
	const char *slow = getenv("BST_TEST_SPOOL_WRITE_DELAY_MS"); /* a slow disk */
	if (slow != NULL) { /* spins on the vDSO clock: the sandbox allows no sleep syscall */
		struct timespec t0, t;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		long ms = strtol(slow, NULL, 10);
		do
			clock_gettime(CLOCK_MONOTONIC, &t);
		while ((t.tv_sec - t0.tv_sec) * 1000L + (t.tv_nsec - t0.tv_nsec) / 1000000L < ms);
	}
#endif
	if (sp->fd < 0 && (sp->wrc = open_tmp(sp)) != 0)
		return;
	for (wchunk *c = sp->inflight; c != NULL; c = c->next) {
		size_t done = 0;
		while (done < c->n) {
			ssize_t w = pwrite(sp->fd, c->d + done, c->n - done,
					   (off_t)(sp->flen + sp->wdone));
			if (w < 0 && errno == EINTR)
				continue;
			if (w <= 0) {
				sp->wrc = w < 0 ? -errno : -ENOSPC;
				return;
			}
			done += (size_t)w;
			sp->wdone += (uint64_t)w;
		}
	}
}

static void write_kick(bst_spool *sp);

static void write_done(void *arg)
{
	bst_spool *sp = arg;
	sp->writing = false;
	if (sp->closing) {
		if (!sp->reading)
			spool_free(sp);
		return;
	}
	uint64_t n = 0;
	for (wchunk *c = sp->inflight; c != NULL; c = c->next)
		n += c->n;
	chunks_free(sp->inflight);
	sp->inflight = NULL;
	sp->qlen -= n;
	if (sp->wrc != 0) {
		/* what did not reach the file is gone: the spool ends at the last whole write, and
		 * every later write or read past it reports the failure */
		if (sp->werr == 0)
			sp->werr = sp->wrc;
		chunks_free(sp->q);
		sp->q = NULL;
		sp->qtail = &sp->q;
		sp->qlen = 0; /* flen stays: nothing of this job counts */
	} else {
		sp->flen += sp->wdone;
	}
	if (sp->q != NULL && sp->werr == 0) {
		write_kick(sp);
		return;
	}
	if (sp->fcb != NULL) {
		bst_spool_flush_cb cb = sp->fcb;
		sp->fcb = NULL;
		cb(sp->fud, sp->werr); /* may close sp */
	}
}

static void write_retry(void *ud)
{
	write_kick(ud);
}

static void write_kick(bst_spool *sp)
{
	if (sp->writing || sp->q == NULL || sp->werr != 0)
		return;
	sp->inflight = sp->q;
	sp->q = NULL;
	sp->qtail = &sp->q;
	sp->writing = true;
	int rc = bst_aio_submit(sp->loop, write_work, write_done, sp);
	if (rc == 0)
		return;
	if (rc == -ESHUTDOWN) { /* the loop is going away: nothing else runs on it */
		write_work(sp);
		write_done(sp);
		return;
	}
	sp->writing = false; /* -EAGAIN: the pool is full; put the chunks back */
	wchunk **t = &sp->inflight;
	while (*t != NULL)
		t = &(*t)->next;
	sp->q = sp->inflight;
	sp->qtail = t;
	sp->inflight = NULL;
	bst_loop_timer_arm(sp->loop, &sp->retry, RETRY_MS, write_retry, sp);
}

static int file_append(bst_spool *sp, const unsigned char *p, size_t n)
{
	if (sp->werr != 0)
		return sp->werr;
	if (sp->dir_fd < 0)
		return -ENOENT;
	wchunk *c = malloc(sizeof *c + n);
	if (c == NULL)
		return -ENOMEM;
	c->next = NULL;
	c->n = n;
	memcpy(c->d, p, n);
	*sp->qtail = c;
	sp->qtail = &c->next;
	sp->qlen += n;
	write_kick(sp);
	return 0;
}

int bst_spool_write_mem(bst_spool *sp, const void *data, size_t len)
{
	const unsigned char *p = data;
	if (sp->flen == 0 && sp->qlen == 0 && sp->mlen < sp->limit) { /* memory first */
		size_t room = (size_t)(sp->limit - sp->mlen);
		size_t take = len < room ? len : room;
		if (sp->mlen + take > sp->mcap) {
			size_t cap = sp->mcap ? sp->mcap : 16384;
			while (cap < sp->mlen + take)
				cap *= 2;
			if (cap > sp->limit)
				cap = (size_t)sp->limit;
			unsigned char *nm = realloc(sp->mem, cap);
			if (nm == NULL)
				return -ENOMEM;
			sp->mem = nm;
			sp->mcap = cap;
		}
		memcpy(sp->mem + sp->mlen, p, take);
		sp->mlen += take;
		p += take;
		len -= take;
	}
	if (len == 0)
		return 0;
	return file_append(sp, p, len);
}

int bst_spool_write(bst_spool *sp, bst_chain *c)
{
	while (bst_chain_len(c) > 0) {
		struct iovec iov[32];
		int n = bst_chain_to_iov(c, iov, 32);
		if (n <= 0)
			return -EINVAL; /* a file segment: bodies here are memory */
		for (int i = 0; i < n; i++) {
			int rc = bst_spool_write_mem(sp, iov[i].iov_base, iov[i].iov_len);
			if (rc != 0)
				return rc;
			bst_chain_consume(c, iov[i].iov_len);
		}
	}
	return 0;
}

int bst_spool_flush(bst_spool *sp, bst_spool_flush_cb cb, void *ud)
{
	if (sp->werr != 0)
		return sp->werr;
	if (sp->qlen == 0)
		return 0;
	sp->fcb = cb;
	sp->fud = ud;
	return 1;
}

/* ---- reading ---- */

static void read_work(void *arg)
{
	bst_spool *sp = arg;
	size_t want = sp->rb->cap;
	size_t got = 0;
	while (got < want) {
		ssize_t r = pread(sp->fd, sp->rb->data + got, want - got, (off_t)(sp->roff + got));
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0) {
			sp->rerr = r < 0 ? -errno : -EIO;
			return;
		}
		got += (size_t)r;
	}
	sp->rb->len = got;
	sp->rerr = 0;
}

static void read_done(void *arg)
{
	bst_spool *sp = arg;
	sp->reading = false;
	bst_buf *b = sp->rb;
	sp->rb = NULL;
	if (sp->closing) {
		bst_buf_unref(b);
		if (!sp->writing)
			spool_free(sp);
		return;
	}
	if (sp->rerr != 0) {
		bst_buf_unref(b);
		b = NULL;
	}
	sp->cb(sp->ud, b, sp->rerr);
}

static bst_buf *copy_out(const unsigned char *p, size_t n)
{
	bst_buf *b = bst_buf_new(n);
	if (b == NULL)
		return NULL;
	memcpy(b->data, p, n);
	b->len = n;
	return b;
}

/* Bytes at file offset foff that are still queued: the chunks are in memory, so no disk. */
static int read_queued(bst_spool *sp, uint64_t foff, size_t max, bst_buf **out)
{
	uint64_t pos = sp->flen;
	for (int pass = 0; pass < 2; pass++) {
		for (wchunk *c = pass == 0 ? sp->inflight : sp->q; c != NULL; c = c->next) {
			if (foff < pos + c->n) {
				size_t at = (size_t)(foff - pos);
				size_t n = c->n - at < max ? c->n - at : max;
				*out = copy_out(c->d + at, n);
				return *out != NULL ? 1 : -ENOMEM;
			}
			pos += c->n;
		}
	}
	return -EINVAL;
}

int bst_spool_read(bst_spool *sp, uint64_t off, size_t max, bst_buf **out, bst_spool_read_cb cb,
		   void *ud)
{
	uint64_t size = bst_spool_size(sp);
	if (off >= size || max == 0)
		return sp->werr != 0 && off >= sp->mlen + sp->flen ? sp->werr : -EINVAL;
	if (sp->reading)
		return -EBUSY;
	if (off < sp->mlen) {
		size_t n = (size_t)(sp->mlen - off) < max ? (size_t)(sp->mlen - off) : max;
		*out = copy_out(sp->mem + off, n);
		return *out != NULL ? 1 : -ENOMEM;
	}
	uint64_t foff = off - sp->mlen;
	if (foff >= sp->flen)
		return read_queued(sp, foff, max, out);
	size_t n = (size_t)(sp->flen - foff) < max ? (size_t)(sp->flen - foff) : max;
	bst_buf *b = bst_buf_new(n);
	if (b == NULL)
		return -ENOMEM;
	sp->rb = b;
	sp->roff = foff;
	sp->cb = cb;
	sp->ud = ud;
	sp->reading = true;
	int rc = bst_aio_submit(sp->loop, read_work, read_done, sp);
	if (rc != 0) {
		sp->reading = false;
		sp->rb = NULL;
		bst_buf_unref(b);
		return rc;
	}
	return 0;
}

void bst_spool_close(bst_spool *sp)
{
	if (sp == NULL)
		return;
	sp->fcb = NULL;
	if (sp->reading || sp->writing) { /* the pool still uses the file: free it after */
		sp->closing = true;
		return;
	}
	spool_free(sp);
}

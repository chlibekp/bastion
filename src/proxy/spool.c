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
#include <unistd.h>

#ifndef O_TMPFILE
#define O_TMPFILE (020000000 | O_DIRECTORY)
#endif

struct bst_spool {
	bst_loop *loop;
	int dir_fd; /* temp_path (borrowed from the config), -1 when there is none */
	int fd;	    /* the temp file, -1 until the first spill */
	uint64_t limit;
	unsigned char *mem;
	size_t mlen, mcap;
	uint64_t flen; /* bytes in the file */
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
	return sp;
}

uint64_t bst_spool_size(const bst_spool *sp)
{
	return sp->mlen + sp->flen;
}

uint64_t bst_spool_spilled(const bst_spool *sp)
{
	return sp->flen;
}

/* The unnamed file: never linked, so it goes when its descriptor does. */
static int open_tmp(bst_spool *sp)
{
	if (sp->dir_fd < 0)
		return -ENOENT;
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

static int file_append(bst_spool *sp, const unsigned char *p, size_t n)
{
#ifdef BST_TEST
	if (getenv("BST_TEST_SPOOL_ENOSPC") != NULL)
		return -ENOSPC; /* a full disk, without filling one */
#endif
	if (sp->fd < 0) {
		int rc = open_tmp(sp);
		if (rc != 0)
			return rc;
	}
	while (n > 0) {
		ssize_t w = pwrite(sp->fd, p, n, (off_t)sp->flen);
		if (w < 0 && errno == EINTR)
			continue;
		if (w < 0)
			return -errno;
		if (w == 0)
			return -ENOSPC;
		p += w;
		n -= (size_t)w;
		sp->flen += (uint64_t)w;
	}
	return 0;
}

int bst_spool_write_mem(bst_spool *sp, const void *data, size_t len)
{
	const unsigned char *p = data;
	if (sp->flen == 0 && sp->mlen < sp->limit) { /* memory first, while nothing spilled */
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
	uint64_t before = sp->flen;
	int rc = file_append(sp, p, len);
	if (rc != 0)
		sp->flen = before; /* a partial write is forgotten: the next one overwrites it */
	return rc;
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
		bst_spool_close(sp);
		return;
	}
	if (sp->rerr != 0) {
		bst_buf_unref(b);
		b = NULL;
	}
	sp->cb(sp->ud, b, sp->rerr);
}

int bst_spool_read(bst_spool *sp, uint64_t off, size_t max, bst_buf **out, bst_spool_read_cb cb,
		   void *ud)
{
	uint64_t size = bst_spool_size(sp);
	if (off >= size || max == 0)
		return -EINVAL;
	if (sp->reading)
		return -EBUSY;
	if (off < sp->mlen) {
		size_t n = (size_t)(sp->mlen - off) < max ? (size_t)(sp->mlen - off) : max;
		bst_buf *b = bst_buf_new(n);
		if (b == NULL)
			return -ENOMEM;
		memcpy(b->data, sp->mem + off, n);
		b->len = n;
		*out = b;
		return 1;
	}
	uint64_t foff = off - sp->mlen;
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
	if (sp->reading) { /* the pool still reads the file: free it when the read is done */
		sp->closing = true;
		return;
	}
	if (sp->fd >= 0)
		close(sp->fd);
	free(sp->mem);
	free(sp);
}

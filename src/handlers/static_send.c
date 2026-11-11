/* Putting the pieces of a file response on the wire: in one chain for the kernel to move
 * (sendfile, splice), or read through the aio pool and sent a chunk at a time. */
#include "handlers/static_priv.h"

#include "core/log.h"
#include "io/aio.h"
#include "proc/worker.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void release_file(void *f)
{
	bst_file_unref(f);
}

int bst_static_send_chain(bst_stream *s, bst_file *f, const bst_piece *p, int n, uint64_t max_chunk)
{
	bst_chain *c = bst_arena_alloc(s->arena, sizeof *c);
	if (c == NULL)
		return -1;
	bst_chain_init(c, s->chain_slab);
	for (int i = 0; i < n; i++) {
		if (p[i].mem != NULL) {
			if (bst_chain_add_mem(c, p[i].mem, 0, p[i].mem->len) != 0)
				goto fail;
			continue;
		}
		for (off_t off = p[i].foff, left = p[i].flen; left > 0;) {
			off_t len = max_chunk > 0 && (uint64_t)left > max_chunk ? (off_t)max_chunk : left;
			/* each segment holds the file open until it is sent or dropped */
			if (bst_chain_add_file_rel(c, f->fd, off, len, release_file, bst_file_ref(f)) != 0) {
				bst_file_unref(f);
				goto fail;
			}
			off += len;
			left -= len;
		}
	}
	if (bst_stream_send_body(s, c, true, NULL, NULL) != 0)
		return 0; /* the stream is gone: nothing more to do, the chain was taken or cleared */
	return 0;
fail:
	bst_chain_clear(c);
	return -1;
}

/* ---- reading on the pool ---- */

enum { RD_IDLE, RD_READING, RD_SENDING };

struct bst_static_rd {
	bst_stream *s;
	bst_loop *loop;
	bst_file *f;
	bst_piece *p;
	int n, i;
	bool open; /* inside a file piece: foff/fleft are live */
	off_t foff, fleft;
	size_t chunk;
	int state;
	bool alive;
	bst_buf *buf; /* the read in flight */
	size_t want;
	ssize_t got;
	struct bst_static_rd **slot;
};
typedef struct bst_static_rd rd;

static void cleanup(rd *r)
{
	bst_buf_unref(r->buf);
	for (int i = 0; i < r->n; i++)
		if (r->p[i].mem != NULL)
			bst_buf_unref(r->p[i].mem);
	bst_file_unref(r->f);
	if (r->slot != NULL && *r->slot == r)
		*r->slot = NULL;
	free(r->p);
	free(r);
}

static void step(rd *r);

static void sent(void *ud, size_t n, int err)
{
	(void)n;
	rd *r = ud;
	if (err != 0) { /* the connection failed under the write: the stream resets us */
		return;
	}
	r->state = RD_IDLE;
	step(r);
}

static void send_chunk(rd *r, bst_chain *c, bool end)
{
	r->state = RD_SENDING;
	if (bst_stream_send_body(r->s, c, end, end ? NULL : sent, r) != 0) {
		r->alive = false; /* the stream is gone; no callback will come */
		cleanup(r);
		return;
	}
	if (end) { /* finished: no on_reset follows, and the stream's memory may be gone already */
		r->slot = NULL;
		r->alive = false;
		cleanup(r);
	}
}

static void read_work(void *arg)
{
	rd *r = arg;
	ssize_t g;
	do
		g = pread(r->f->fd, r->buf->data, r->want, r->foff);
	while (g < 0 && errno == EINTR);
	r->got = g;
}

static void read_done(void *arg)
{
	rd *r = arg;
	r->state = RD_IDLE;
	if (!r->alive) {
		cleanup(r);
		return;
	}
	if (r->got < 0 || (size_t)r->got != r->want) {
		/* The file shrank under us (or the disk failed): the head promised more than exists.
		 * Ending the response here would be a lie the client cannot see, so abort. */
		bst_log(BST_LOG_WARN, "static: file read came up short (%zd of %zu): aborting the response",
			r->got, r->want);
		bst_stream *s = r->s;
		r->alive = false;
		cleanup(r);
		s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
		return;
	}
	r->buf->len = (size_t)r->got;
	r->foff += r->got;
	r->fleft -= r->got;
	bool piece_done = r->fleft == 0;
	if (piece_done) {
		r->open = false;
		r->i++;
	}
	bst_chain *c = bst_arena_alloc(r->s->arena, sizeof *c);
	if (c == NULL || (bst_chain_init(c, r->s->chain_slab), bst_chain_add_mem(c, r->buf, 0, r->buf->len)) != 0) {
		bst_stream *s = r->s;
		r->alive = false;
		cleanup(r);
		s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
		return;
	}
	bst_buf_unref(r->buf);
	r->buf = NULL;
	send_chunk(r, c, piece_done && r->i == r->n);
}

static void fail_reset(rd *r)
{
	bst_stream *s = r->s;
	r->alive = false;
	cleanup(r);
	s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
}

static void step(rd *r)
{
	while (r->i < r->n) {
		bst_piece *pc = &r->p[r->i];
		if (pc->mem != NULL) {
			bst_chain *c = bst_arena_alloc(r->s->arena, sizeof *c);
			if (c == NULL)
				return fail_reset(r);
			bst_chain_init(c, r->s->chain_slab);
			if (bst_chain_add_mem(c, pc->mem, 0, pc->mem->len) != 0)
				return fail_reset(r);
			r->i++;
			send_chunk(r, c, r->i == r->n);
			return;
		}
		if (!r->open) {
			r->open = true;
			r->foff = pc->foff;
			r->fleft = pc->flen;
		}
		if (r->fleft == 0) {
			r->open = false;
			r->i++;
			continue;
		}
		r->want = (uint64_t)r->fleft < r->chunk ? (size_t)r->fleft : r->chunk;
		r->buf = bst_buf_new(r->want);
		if (r->buf == NULL)
			return fail_reset(r);
		r->state = RD_READING;
		int rc = bst_aio_submit(r->loop, read_work, read_done, r);
		if (rc != 0) {
			r->state = RD_IDLE;
			bst_log(BST_LOG_WARN, "static: the read queue is full: aborting the response");
			return fail_reset(r);
		}
		return;
	}
	/* nothing left and nothing sent last: close the body */
	bst_chain *c = bst_arena_alloc(r->s->arena, sizeof *c);
	if (c == NULL)
		return fail_reset(r);
	bst_chain_init(c, r->s->chain_slab);
	send_chunk(r, c, true);
}

int bst_static_send_read(bst_stream *s, bst_file *f, const bst_piece *p, int n, size_t chunk,
			 struct bst_static_rd **slot)
{
	rd *r = calloc(1, sizeof *r);
	if (r == NULL)
		return -1;
	r->p = malloc((size_t)(n > 0 ? n : 1) * sizeof *r->p);
	if (r->p == NULL) {
		free(r);
		return -1;
	}
	memcpy(r->p, p, (size_t)n * sizeof *r->p);
	for (int i = 0; i < n; i++)
		if (r->p[i].mem != NULL)
			bst_buf_ref(r->p[i].mem);
	r->n = n;
	r->s = s;
	r->loop = bst_worker_loop(s->worker);
	r->f = bst_file_ref(f);
	r->chunk = chunk;
	r->alive = true;
	r->slot = slot;
	*slot = r;
	step(r);
	return 0;
}

void bst_static_stream_abort(struct bst_static_rd *r)
{
	if (r == NULL)
		return;
	if (r->slot != NULL) { /* the owner's memory is about to go: stop pointing into it */
		*r->slot = NULL;
		r->slot = NULL;
	}
	r->alive = false;
	if (r->state != RD_READING) /* a read in flight frees it when it lands */
		cleanup(r);
}

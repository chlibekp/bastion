#include "core/chain.h"

#include <stdbool.h>

struct bst_seg {
	struct bst_seg *next;
	bst_buf *buf; /* NULL for a file segment */
	size_t off, len;
	int fd;
	off_t foff, flen;
	bst_chain_release_fn release;
	void *arg;
};

bst_slab *bst_chain_slab_new(size_t per_chunk)
{
	return bst_slab_new(sizeof(struct bst_seg), per_chunk);
}

void bst_chain_init(bst_chain *c, bst_slab *slab)
{
	c->slab = slab;
	c->head = c->tail = NULL;
	c->len = 0;
}

static void push(bst_chain *c, struct bst_seg *s)
{
	s->next = NULL;
	if (c->tail)
		c->tail->next = s;
	else
		c->head = s;
	c->tail = s;
}

int bst_chain_add_mem(bst_chain *c, bst_buf *b, size_t off, size_t len)
{
	if (b == NULL || off > b->len || len > b->len - off)
		return -1;
	if (len == 0)
		return 0;
	if (len > (uint64_t)INT64_MAX - c->len)
		return -1;
	struct bst_seg *s = bst_slab_get(c->slab);
	if (s == NULL)
		return -1;
	*s = (struct bst_seg){ .buf = bst_buf_ref(b), .off = off, .len = len, .fd = -1 };
	push(c, s);
	c->len += len;
	return 0;
}

int bst_chain_add_file_rel(bst_chain *c, int fd, off_t off, off_t len,
			   bst_chain_release_fn release, void *arg)
{
	if (off < 0 || len < 0 || off > INT64_MAX - len)
		return -1;
	if (len == 0)
		return 0;
	if ((uint64_t)len > (uint64_t)INT64_MAX - c->len)
		return -1;
	struct bst_seg *s = bst_slab_get(c->slab);
	if (s == NULL)
		return -1;
	*s = (struct bst_seg){ .fd = fd, .foff = off, .flen = len, .release = release, .arg = arg };
	push(c, s);
	c->len += (uint64_t)len;
	return 0;
}

int bst_chain_add_file(bst_chain *c, int fd, off_t off, off_t len)
{
	return bst_chain_add_file_rel(c, fd, off, len, NULL, NULL);
}

uint64_t bst_chain_len(const bst_chain *c)
{
	return c->len;
}

static void drop_head(bst_chain *c)
{
	struct bst_seg *s = c->head;
	c->head = s->next;
	if (c->head == NULL)
		c->tail = NULL;
	if (s->buf)
		bst_buf_unref(s->buf);
	else if (s->release)
		s->release(s->arg);
	bst_slab_put(c->slab, s);
}

void bst_chain_consume(bst_chain *c, uint64_t n)
{
	if (n > c->len)
		n = c->len;
	c->len -= n;
	while (n > 0 && c->head) {
		struct bst_seg *s = c->head;
		uint64_t have = s->buf ? (uint64_t)s->len : (uint64_t)s->flen;
		if (n >= have) {
			n -= have;
			drop_head(c);
		} else {
			if (s->buf) {
				s->off += (size_t)n;
				s->len -= (size_t)n;
			} else {
				s->foff += (off_t)n;
				s->flen -= (off_t)n;
			}
			n = 0;
		}
	}
}

int bst_chain_to_iov(const bst_chain *c, struct iovec *iov, int max)
{
	int n = 0;
	for (const struct bst_seg *s = c->head; s && s->buf && n < max; s = s->next, n++) {
		iov[n].iov_base = s->buf->data + s->off;
		iov[n].iov_len = s->len;
	}
	return n;
}

int bst_chain_front_bufs(const bst_chain *c, bst_buf **bufs, int max)
{
	int n = 0;
	for (const struct bst_seg *s = c->head; s && s->buf && n < max; s = s->next, n++)
		bufs[n] = s->buf;
	return n;
}

int bst_chain_front_file(const bst_chain *c, int *fd, off_t *off, off_t *len)
{
	if (c->head == NULL || c->head->buf != NULL)
		return 0;
	*fd = c->head->fd;
	*off = c->head->foff;
	*len = c->head->flen;
	return 1;
}

void bst_chain_clear(bst_chain *c)
{
	while (c->head)
		drop_head(c);
	c->len = 0;
}

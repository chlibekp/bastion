#include "handlers/static.h"

#include "core/log.h"
#include "handlers/resolve.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>

typedef struct sctx {
	bst_file_req *req; /* the open in flight: cancelled when the stream is reset */
	bool head;
} sctx;

static int status_for(int err)
{
	switch (err) {
	case ENOENT:
	case ENOTDIR:
	case ELOOP:
	case EXDEV:
	case ENAMETOOLONG:
		return 404;
	case EACCES:
	case EPERM:
	case ENXIO:
		return 403;
	case EAGAIN:
	case ESHUTDOWN:
		return 503;
	default:
		return 500;
	}
}

static void redirect_to_dir(bst_stream *s)
{
	const bst_req_head *h = &s->req.head;
	size_t n = (size_t)h->path.len + 1 + (h->has_query ? (size_t)h->query.len + 1 : 0);
	char *b = bst_arena_alloc(s->arena, n + 1);
	if (b == NULL) {
		(void)bst_send_error(s, 500);
		return;
	}
	memcpy(b, h->path.p, h->path.len);
	b[h->path.len] = '/';
	if (h->has_query) {
		b[h->path.len + 1] = '?';
		memcpy(b + h->path.len + 2, h->query.p, h->query.len);
	}
	(void)bst_send_error_hdr(s, 301, BST_S("Location"), (bst_str){ b, (uint32_t)n });
}

static void release_file(void *f)
{
	bst_file_unref(f);
}

static void send_file(bst_stream *s, bst_file *f, bool head)
{
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = 200;
	h.content_length = (int64_t)f->size;
	bst_headers_init(&h.headers, s->arena);
	if (bst_headers_add(&h.headers, BST_S("Content-Type"), BST_S("application/octet-stream")) != 0) {
		bst_file_unref(f);
		(void)bst_send_error(s, 500);
		return;
	}
	bool empty = head || f->size == 0;
	if (bst_stream_send_head(s, &h, empty) != 0 || empty) {
		bst_file_unref(f);
		return;
	}
	bst_chain *c = bst_arena_alloc(s->arena, sizeof *c);
	if (c == NULL) {
		bst_file_unref(f);
		return;
	}
	bst_chain_init(c, s->chain_slab);
	/* the segment keeps the file (and so the descriptor) alive until it is sent or dropped */
	if (bst_chain_add_file_rel(c, f->fd, 0, f->size, release_file, f) != 0) {
		bst_file_unref(f);
		return;
	}
	(void)bst_stream_send_body(s, c, true, NULL, NULL);
}

static void opened(void *ud, bst_file *f, int err)
{
	bst_stream *s = ud;
	sctx *c = s->hctx;
	c->req = NULL;
	if (f == NULL) {
		if (status_for(err) >= 500 && err != EAGAIN && err != ESHUTDOWN)
			bst_log(BST_LOG_WARN, "static: opening \"%.*s\" failed: %s", (int)s->uri.len,
				s->uri.p, strerror(err));
		(void)bst_send_error(s, status_for(err));
		return;
	}
	if (S_ISDIR(f->mode)) {
		bool slash = s->uri.len > 0 && s->uri.p[s->uri.len - 1] == '/';
		bst_file_unref(f);
		if (!slash)
			redirect_to_dir(s);
		else
			(void)bst_send_error(s, 404); /* no index or listing yet */
		return;
	}
	if (!S_ISREG(f->mode)) { /* a FIFO, a device, a socket: never read */
		bst_file_unref(f);
		(void)bst_send_error(s, 403);
		return;
	}
	send_file(s, f, c->head);
}

static void serve(bst_stream *s)
{
	sctx *c = s->hctx;
	const bst_cfg_files *fc = &s->cfg->files;
	const char *rel = s->uri.p + 1;
	size_t rel_len = s->uri.len > 0 ? s->uri.len - 1 : 0;
	if (fc->alias) {
		if (s->loc == NULL || s->loc->re != NULL || s->loc->pattern == NULL) {
			bst_log(BST_LOG_WARN, "static: alias needs a prefix location");
			(void)bst_send_error(s, 500);
			return;
		}
		size_t pl = strlen(s->loc->pattern);
		if (pl > s->uri.len || memcmp(s->uri.p, s->loc->pattern, pl) != 0) {
			(void)bst_send_error(s, 404);
			return;
		}
		rel = s->uri.p + pl;
		rel_len = s->uri.len - pl;
	}
	bst_file_policy p = { fc->symlinks, fc->dotfiles_allow };
	c->req = bst_file_open(s->worker, fc->root->fd, (bst_str){ rel, (uint32_t)rel_len }, p, opened,
			       s);
}

static void on_request(bst_stream *s)
{
	sctx *c = bst_arena_alloc(s->arena, sizeof *c);
	if (c == NULL) {
		(void)bst_send_error(s, 500);
		return;
	}
	memset(c, 0, sizeof *c);
	s->hctx = c;
	bst_method m = s->req.head.method;
	if (m != BST_M_GET && m != BST_M_HEAD) {
		(void)bst_send_error(s, 405);
		return;
	}
	c->head = m == BST_M_HEAD;
	if (s->req.framing.kind == BST_FRAMING_NONE)
		serve(s);
	else
		bst_stream_read_body(s, SIZE_MAX);
}

static void on_body(bst_stream *s, bst_chain *in, bool end)
{
	bst_chain_clear(in);
	if (end)
		serve(s);
}

static void on_reset(bst_stream *s, bst_stream_err why)
{
	(void)why;
	sctx *c = s->hctx;
	if (c != NULL)
		bst_file_open_cancel(c->req);
}

const bst_handler_ops bst_static_handler = {
	.on_request = on_request,
	.on_body = on_body,
	.on_reset = on_reset,
};

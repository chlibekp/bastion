/* The static file handler: GET and HEAD of a file below `root` (or `alias`), with validators,
 * conditional requests and byte ranges. Opening is resolve.c; putting bytes on the wire is
 * static_send.c. */
#include "handlers/static.h"

#include "core/log.h"
#include "handlers/mime.h"
#include "handlers/range.h"
#include "handlers/resolve.h"
#include "handlers/static_priv.h"
#include "http/conditional.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>

typedef struct sctx {
	bst_file_req *req;	      /* the open in flight: cancelled when the stream is reset */
	struct bst_static_rd *rd;     /* the read-and-send in flight, with sendfile off */
	bool head;
} sctx;

#define ALLOW "GET, HEAD, OPTIONS"

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

static bst_str arena_str(bst_stream *s, const char *p, size_t n)
{
	char *b = bst_arena_alloc(s->arena, n + 1);
	if (b == NULL)
		return (bst_str){ NULL, 0 };
	memcpy(b, p, n);
	b[n] = '\0';
	return (bst_str){ b, (uint32_t)n };
}

static bst_buf *mem_piece(const char *p, size_t n)
{
	bst_buf *b = bst_buf_new(n);
	if (b == NULL)
		return NULL;
	memcpy(b->data, p, n);
	b->len = n;
	return b;
}

static void drop_pieces(bst_piece *p, int n)
{
	for (int i = 0; i < n; i++)
		bst_buf_unref(p[i].mem); /* NULL for a file piece is fine */
}

/* Everything a 200, 206 or 304 carries besides the framing. */
typedef struct validators {
	bst_str etag, lastmod;
	bst_str type;
} validators;

static int add_common(bst_stream *s, bst_resp_head *h, const validators *v, bool ranges)
{
	if (v->lastmod.len > 0 && bst_headers_add(&h->headers, BST_S("Last-Modified"), v->lastmod) != 0)
		return -1;
	if (v->etag.len > 0 && bst_headers_add(&h->headers, BST_S("ETag"), v->etag) != 0)
		return -1;
	if (ranges && bst_headers_add(&h->headers, BST_S("Accept-Ranges"), BST_S("bytes")) != 0)
		return -1;
	(void)s;
	return 0;
}

static bool hex_boundary(bst_stream *s, char out[33])
{
	unsigned char r[16];
	static const char hex[] = "0123456789abcdef";
	(void)s;
	if (getrandom(r, sizeof r, 0) != (ssize_t)sizeof r)
		return false;
	for (size_t i = 0; i < sizeof r; i++) {
		out[2 * i] = hex[r[i] >> 4];
		out[2 * i + 1] = hex[r[i] & 15];
	}
	out[32] = '\0';
	return true;
}

/* Sends the head and the pieces. Takes the caller's reference of f and of the mem pieces. */
static void deliver(bst_stream *s, sctx *c, bst_file *f, bst_resp_head *h, bst_piece *p, int n,
		    bool head_only)
{
	const bst_cfg_files *fc = &s->cfg->files;
	bool empty = head_only || h->content_length == 0;
	if (bst_stream_send_head(s, h, empty) != 0 || empty)
		goto done;
	if (fc->sendfile) {
		if (bst_static_send_chain(s, f, p, n, fc->sendfile_max_chunk) != 0) {
			bst_log(BST_LOG_WARN, "static: out of memory building a response: aborted");
			s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
		}
	} else if (bst_static_send_read(s, f, p, n, (size_t)fc->read_chunk_size, &c->rd) != 0) {
		s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
	}
done:
	drop_pieces(p, n);
	bst_file_unref(f);
}

static void respond_file(bst_stream *s, sctx *c, bst_file *f)
{
	const bst_cfg_files *fc = &s->cfg->files;
	const bst_req_head *rq = &s->req.head;
	validators v = { { "", 0 }, { "", 0 }, { NULL, 0 } };
	const char *type = bst_mime_lookup(&fc->mime, s->uri.p, s->uri.len, fc->default_type);
	char tmp[BST_ETAG_MAX];
	if (fc->etag) {
		size_t n = bst_etag_format(f->mtime_ns, (int64_t)f->size, tmp, sizeof tmp);
		v.etag = arena_str(s, tmp, n);
	}
	time_t mt = (time_t)(f->mtime_ns / 1000000000ll);
	char date[BST_HTTP_DATE_LEN + 1];
	bool has_mt = bst_http_date_format(mt, date) == BST_HTTP_DATE_LEN;
	if (has_mt)
		v.lastmod = arena_str(s, date, BST_HTTP_DATE_LEN);
	v.type = arena_str(s, type, strlen(type));
	if (v.type.p == NULL || (fc->etag && v.etag.p == NULL)) {
		bst_file_unref(f);
		(void)bst_send_error(s, 500);
		return;
	}

	bst_validators val = { fc->etag, v.etag, has_mt, mt };
	bst_cond_result cr = bst_evaluate_preconditions(&rq->headers, &val, rq->method);
	if (cr == BST_COND_412) {
		bst_file_unref(f);
		(void)bst_send_error(s, 412);
		return;
	}
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	bst_headers_init(&h.headers, s->arena);
	if (cr == BST_COND_304) {
		h.status = 304;
		h.content_length = -1;
		if (add_common(s, &h, &v, false) == 0)
			(void)bst_stream_send_head(s, &h, true);
		else
			(void)bst_send_error(s, 500);
		bst_file_unref(f);
		return;
	}

	/* Range, only when If-Range allows it. A Range on a HEAD gets the 206 head, as on GET. */
	bst_range *rg = NULL;
	int nr = 0, rs = BST_RANGE_NONE;
	const bst_header *rh = bst_headers_get(&rq->headers, BST_H_RANGE);
	if (rh != NULL && (rq->method == BST_M_GET || rq->method == BST_M_HEAD)) {
		const bst_header *ir = bst_headers_get(&rq->headers, BST_H_IF_RANGE);
		if (ir == NULL || bst_if_range_ok(ir->value, v.etag, has_mt, mt)) {
			rg = bst_arena_alloc(s->arena, (size_t)fc->max_ranges * sizeof *rg);
			if (rg == NULL) {
				bst_file_unref(f);
				(void)bst_send_error(s, 500);
				return;
			}
			rs = bst_range_parse(rh->value, f->size, rg, (int)fc->max_ranges, &nr);
		}
	}
	if (rs == BST_RANGE_416) {
		char cr416[40];
		int l = snprintf(cr416, sizeof cr416, "bytes */%lld", (long long)f->size);
		bst_file_unref(f);
		(void)bst_send_error_hdr(s, 416, BST_S("Content-Range"), arena_str(s, cr416, (size_t)l));
		return;
	}

	bst_piece pieces[1 + 2 * 1000 + 1];
	int np = 0;
	bool ok = true;
	h.status = 200;
	h.content_length = (int64_t)f->size;
	if (rs == BST_RANGE_OK && nr == 1) {
		char b[80];
		int l = snprintf(b, sizeof b, "bytes %lld-%lld/%lld", (long long)rg[0].start,
				 (long long)rg[0].end, (long long)f->size);
		h.status = 206;
		h.content_length = rg[0].end - rg[0].start + 1;
		ok = bst_headers_add(&h.headers, BST_S("Content-Type"), v.type) == 0 &&
		     bst_headers_add(&h.headers, BST_S("Content-Range"), arena_str(s, b, (size_t)l)) == 0;
		pieces[np++] = (bst_piece){ NULL, rg[0].start, rg[0].end - rg[0].start + 1 };
	} else if (rs == BST_RANGE_OK) {
		char bnd[33];
		ok = hex_boundary(s, bnd);
		int64_t total = 0;
		for (int i = 0; ok && i < nr; i++) {
			char part[320];
			int l = snprintf(part, sizeof part,
					 "%s--%s\r\nContent-Type: %s\r\nContent-Range: bytes %lld-%lld/%lld\r\n\r\n",
					 i ? "\r\n" : "", bnd, type, (long long)rg[i].start,
					 (long long)rg[i].end, (long long)f->size);
			bst_buf *m = l > 0 && (size_t)l < sizeof part ? mem_piece(part, (size_t)l) : NULL;
			if (m == NULL) {
				ok = false;
				break;
			}
			pieces[np++] = (bst_piece){ m, 0, 0 };
			pieces[np++] = (bst_piece){ NULL, rg[i].start, rg[i].end - rg[i].start + 1 };
			total += l + (rg[i].end - rg[i].start + 1);
		}
		if (ok) {
			char tail[64];
			int l = snprintf(tail, sizeof tail, "\r\n--%s--\r\n", bnd);
			bst_buf *m = mem_piece(tail, (size_t)l);
			if (m == NULL)
				ok = false;
			else {
				pieces[np++] = (bst_piece){ m, 0, 0 };
				total += l;
			}
		}
		char ct[96];
		int l = snprintf(ct, sizeof ct, "multipart/byteranges; boundary=%s", bnd);
		h.status = 206;
		h.content_length = total;
		ok = ok && bst_headers_add(&h.headers, BST_S("Content-Type"), arena_str(s, ct, (size_t)l)) == 0;
	} else {
		ok = bst_headers_add(&h.headers, BST_S("Content-Type"), v.type) == 0;
		if (f->size > 0)
			pieces[np++] = (bst_piece){ NULL, 0, f->size };
	}
	if (!ok || add_common(s, &h, &v, true) != 0) {
		drop_pieces(pieces, np);
		bst_file_unref(f);
		(void)bst_send_error(s, 500);
		return;
	}
	deliver(s, c, f, &h, pieces, np, c->head);
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
	respond_file(s, c, f);
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
	if (m == BST_M_OPTIONS) {
		(void)bst_send_error_hdr(s, 204, BST_S("Allow"), BST_S(ALLOW));
		return;
	}
	if (m != BST_M_GET && m != BST_M_HEAD) {
		(void)bst_send_error_hdr(s, 405, BST_S("Allow"), BST_S(ALLOW));
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
	if (c == NULL)
		return;
	bst_file_open_cancel(c->req);
	bst_static_stream_abort(c->rd);
	c->rd = NULL;
}

const bst_handler_ops bst_static_handler = {
	.on_request = on_request,
	.on_body = on_body,
	.on_reset = on_reset,
};

#include "filters/compress.h"

#include "core/buf.h"
#include "core/log.h"
#include "http/accept_encoding.h"
#include "proc/worker.h"

#define ZSTD_STATIC_LINKING_ONLY /* ZSTD_createCCtx_advanced: our allocator */
#include <brotli/encode.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib-ng.h>
#include <zstd.h>

#define OBUF 16384
#define IN_CHUNK 65536
#define AHDR 16 /* allocation header: the size, for the budget */

typedef enum { OP_CONT, OP_FLUSH, OP_END } cz_op;

typedef struct cz {
	bst_filter f; /* first: the filter is the state */
	bst_encoding enc;
	bst_worker *w;
	ZSTD_CCtx *zs;
	BrotliEncoderState *br;
	zng_stream gz;
	bool gz_init;
	bool done;
	bst_buf *ob; /* the output buffer being filled */
	bst_chain *out;
} cz;

static unsigned g_active;

unsigned bst_compress_active(void)
{
	return g_active;
}

/* ---- allocators charged to the worker's memory budget ---- */

static void *cz_alloc(void *opaque, size_t n)
{
	cz *z = opaque;
	if (n > SIZE_MAX - AHDR)
		return NULL;
	if (z->w != NULL && !bst_worker_mem_charge(z->w, n + AHDR))
		return NULL;
	unsigned char *p = malloc(n + AHDR);
	if (p == NULL) {
		if (z->w != NULL)
			bst_worker_mem_release(z->w, n + AHDR);
		return NULL;
	}
	memcpy(p, &n, sizeof n);
	return p + AHDR;
}

static void cz_free(void *opaque, void *ptr)
{
	cz *z = opaque;
	if (ptr == NULL)
		return;
	unsigned char *p = (unsigned char *)ptr - AHDR;
	size_t n;
	memcpy(&n, p, sizeof n);
	free(p);
	if (z->w != NULL)
		bst_worker_mem_release(z->w, n + AHDR);
}

static void *gz_alloc(void *opaque, unsigned items, unsigned size)
{
	return cz_alloc(opaque, (size_t)items * size);
}

static void cz_end(cz *z)
{
	if (z->done)
		return;
	z->done = true;
	if (z->zs != NULL)
		ZSTD_freeCCtx(z->zs);
	if (z->br != NULL)
		BrotliEncoderDestroyInstance(z->br);
	if (z->gz_init)
		(void)zng_deflateEnd(&z->gz);
	z->zs = NULL;
	z->br = NULL;
	z->gz_init = false;
	bst_buf_unref(z->ob);
	z->ob = NULL;
	g_active--;
}

static int cz_init(cz *z, const bst_cfg_compress *cfg)
{
	switch (z->enc) {
	case BST_ENC_ZSTD: {
		ZSTD_customMem m = { cz_alloc, cz_free, z };
		z->zs = ZSTD_createCCtx_advanced(m);
		if (z->zs == NULL ||
		    ZSTD_isError(ZSTD_CCtx_setParameter(z->zs, ZSTD_c_compressionLevel, cfg->level_zstd)) ||
		    ZSTD_isError(ZSTD_CCtx_setParameter(z->zs, ZSTD_c_windowLog, (int)cfg->window)))
			return -1;
		return 0;
	}
	case BST_ENC_BR:
		z->br = BrotliEncoderCreateInstance(cz_alloc, cz_free, z);
		if (z->br == NULL ||
		    !BrotliEncoderSetParameter(z->br, BROTLI_PARAM_QUALITY, (uint32_t)cfg->level_br) ||
		    !BrotliEncoderSetParameter(z->br, BROTLI_PARAM_LGWIN, cfg->window))
			return -1;
		return 0;
	case BST_ENC_GZIP: {
		z->gz.zalloc = gz_alloc;
		z->gz.zfree = cz_free;
		z->gz.opaque = z;
		int wb = cfg->window > 15 ? 15 : (int)cfg->window;
		if (zng_deflateInit2(&z->gz, cfg->level_gzip, Z_DEFLATED, wb + 16, 8,
				     Z_DEFAULT_STRATEGY) != Z_OK)
			return -1;
		z->gz_init = true;
		return 0;
	}
	default:
		return -1;
	}
}

/* ---- output ---- */

static int ospace(cz *z, unsigned char **p, size_t *avail)
{
	if (z->ob != NULL && z->ob->len == z->ob->cap) {
		int rc = bst_chain_add_mem(z->out, z->ob, 0, z->ob->len);
		bst_buf_unref(z->ob);
		z->ob = NULL;
		if (rc != 0)
			return -1;
	}
	if (z->ob == NULL) {
		z->ob = bst_buf_new(OBUF);
		if (z->ob == NULL)
			return -1;
	}
	*p = z->ob->data + z->ob->len;
	*avail = z->ob->cap - z->ob->len;
	return 0;
}

static int ospill(cz *z)
{
	if (z->ob == NULL || z->ob->len == 0)
		return 0;
	int rc = bst_chain_add_mem(z->out, z->ob, 0, z->ob->len);
	bst_buf_unref(z->ob);
	z->ob = NULL;
	return rc;
}

static int step(cz *z, const unsigned char *in, size_t len, cz_op op)
{
	unsigned char *p;
	size_t avail;
	switch (z->enc) {
	case BST_ENC_ZSTD: {
		ZSTD_inBuffer ib = { in, len, 0 };
		ZSTD_EndDirective d = op == OP_CONT ? ZSTD_e_continue : op == OP_FLUSH ? ZSTD_e_flush : ZSTD_e_end;
		for (;;) {
			if (ospace(z, &p, &avail) != 0)
				return -1;
			ZSTD_outBuffer ob = { p, avail, 0 };
			size_t r = ZSTD_compressStream2(z->zs, &ob, &ib, d);
			if (ZSTD_isError(r))
				return -1;
			z->ob->len += ob.pos;
			if (d == ZSTD_e_continue ? ib.pos == ib.size : r == 0)
				return 0;
		}
	}
	case BST_ENC_BR: {
		size_t ai = len;
		const uint8_t *ni = in;
		BrotliEncoderOperation bo = op == OP_CONT ? BROTLI_OPERATION_PROCESS
				 : op == OP_FLUSH ? BROTLI_OPERATION_FLUSH : BROTLI_OPERATION_FINISH;
		for (;;) {
			if (ospace(z, &p, &avail) != 0)
				return -1;
			size_t ao = avail;
			uint8_t *no = p;
			if (!BrotliEncoderCompressStream(z->br, bo, &ai, &ni, &ao, &no, NULL))
				return -1;
			z->ob->len += avail - ao;
			if (bo == BROTLI_OPERATION_FINISH) {
				if (BrotliEncoderIsFinished(z->br))
					return 0;
			} else if (ai == 0 && !BrotliEncoderHasMoreOutput(z->br)) {
				return 0;
			}
		}
	}
	case BST_ENC_GZIP: {
		z->gz.next_in = in;
		z->gz.avail_in = (uint32_t)len; /* len <= IN_CHUNK */
		int fl = op == OP_CONT ? Z_NO_FLUSH : op == OP_FLUSH ? Z_SYNC_FLUSH : Z_FINISH;
		for (;;) {
			if (ospace(z, &p, &avail) != 0)
				return -1;
			z->gz.next_out = p;
			z->gz.avail_out = (uint32_t)avail;
			int r = zng_deflate(&z->gz, fl);
			if (r == Z_STREAM_ERROR)
				return -1;
			z->ob->len += avail - z->gz.avail_out;
			if (fl == Z_FINISH) {
				if (r == Z_STREAM_END)
					return 0;
			} else if (z->gz.avail_in == 0 && z->gz.avail_out != 0) {
				return 0;
			}
		}
	}
	default:
		return -1;
	}
}

/* ---- the filter ---- */

static int cz_on_body(bst_filter *f, bst_chain *c, bool end)
{
	cz *z = (cz *)f;
	if (z->done)
		return 0;
	bst_chain out;
	bst_chain_init(&out, c->slab);
	z->out = &out;
	bool any = bst_chain_len(c) > 0;
	unsigned char buf[IN_CHUNK];
	while (bst_chain_len(c) > 0) {
		int fd;
		off_t off, flen;
		const unsigned char *in;
		size_t n;
		if (bst_chain_front_file(c, &fd, &off, &flen)) {
			size_t want = (uint64_t)flen < sizeof buf ? (size_t)flen : sizeof buf;
			ssize_t r = pread(fd, buf, want, off);
			if (r < 0 && errno == EINTR)
				continue;
			if (r <= 0) {
				bst_log(BST_LOG_ERROR, "compress: reading the response body failed: %s",
					r < 0 ? strerror(errno) : "file shorter than its length");
				goto fail;
			}
			in = buf;
			n = (size_t)r;
		} else {
			struct iovec iov;
			if (bst_chain_to_iov(c, &iov, 1) != 1)
				goto fail;
			in = iov.iov_base;
			n = iov.iov_len < IN_CHUNK ? iov.iov_len : IN_CHUNK;
		}
		if (step(z, in, n, OP_CONT) != 0)
			goto fail;
		bst_chain_consume(c, n);
	}
	if ((end || any) && step(z, NULL, 0, end ? OP_END : OP_FLUSH) != 0)
		goto fail;
	if (ospill(z) != 0)
		goto fail;
	bst_chain_clear(c);
	(void)bst_chain_move(c, &out); /* c is empty: cannot overflow */
	z->out = NULL;
	if (end)
		cz_end(z);
	return 0;
fail:
	bst_log(BST_LOG_ERROR, "compress: %s failed; the response is cut short",
		bst_encoding_name(z->enc).p);
	bst_chain_clear(&out);
	z->out = NULL;
	cz_end(z);
	return -1;
}

static void cz_release(bst_filter *f)
{
	cz_end((cz *)f);
}

static const bst_filter_ops cz_ops = { .on_head = NULL, .on_body = cz_on_body, .release = cz_release };

/* ---- the decision at the head ---- */

static bool type_ok(const bst_cfg_compress *cfg, const bst_headers *hs)
{
	const bst_header *ct = bst_headers_get(hs, BST_H_CONTENT_TYPE);
	if (ct == NULL)
		return false;
	uint32_t n = 0;
	while (n < ct->value.len && ct->value.p[n] != ';' && ct->value.p[n] != ' ' && ct->value.p[n] != '\t')
		n++;
	bst_str mt = { ct->value.p, n };
	for (size_t i = 0; i < cfg->ntypes; i++) {
		bst_str t = cfg->types[i];
		if (t.len >= 2 && t.p[t.len - 1] == '*' && t.p[t.len - 2] == '/') {
			if (mt.len >= t.len - 1 &&
			    bst_str_ieq((bst_str){ mt.p, t.len - 1 }, (bst_str){ t.p, t.len - 1 }))
				return true;
		} else if (bst_str_ieq(mt, t)) {
			return true;
		}
	}
	return false;
}

/* Every Accept-Encoding line joined with ", " (one line: no copy). */
static bst_str accept_encoding(bst_stream *s)
{
	const bst_headers *hs = &s->req.head.headers;
	size_t total = 0, lines = 0;
	for (const bst_header *h = bst_headers_next(hs, NULL, BST_H_ACCEPT_ENCODING); h != NULL;
	     h = bst_headers_next(hs, h, BST_H_ACCEPT_ENCODING)) {
		total += h->value.len + 2;
		lines++;
	}
	if (lines == 0)
		return BST_S("");
	if (lines == 1)
		return bst_headers_get(hs, BST_H_ACCEPT_ENCODING)->value;
	if (total > UINT32_MAX)
		return BST_S("");
	char *b = bst_arena_alloc(s->arena, total);
	if (b == NULL)
		return BST_S("");
	size_t o = 0;
	for (const bst_header *h = bst_headers_next(hs, NULL, BST_H_ACCEPT_ENCODING); h != NULL;
	     h = bst_headers_next(hs, h, BST_H_ACCEPT_ENCODING)) {
		if (o > 0) {
			b[o++] = ',';
			b[o++] = ' ';
		}
		memcpy(b + o, h->value.p, h->value.len);
		o += h->value.len;
	}
	return (bst_str){ b, (uint32_t)o };
}

/* The head's header list is shared with the handler's: give it its own array first. */
static int own_headers(bst_stream *s, bst_resp_head *h)
{
	bst_headers n;
	bst_headers_init(&n, s->arena);
	for (uint32_t i = 0; i < h->headers.n; i++)
		if (bst_headers_add(&n, h->headers.v[i].name, h->headers.v[i].value) != 0)
			return -1;
	h->headers = n;
	return 0;
}

static void add_vary(bst_resp_head *h)
{
	if (bst_headers_list_has(&h->headers, BST_H_VARY, BST_S("*")) ||
	    bst_headers_list_has(&h->headers, BST_H_VARY, BST_S("accept-encoding")))
		return;
	(void)bst_headers_add(&h->headers, BST_S("Vary"), BST_S("Accept-Encoding"));
}

static bool has_filter(const bst_stream *s)
{
	for (const bst_filter *f = s->filters; f != NULL; f = f->next)
		if (f->ops == &cz_ops)
			return true;
	return false;
}

void bst_compress_attach(bst_stream *s, bst_resp_head *h, bool end)
{
	const bst_cfg_compress *cfg = &s->cfg->compress;
	if (cfg->encodings == 0 || has_filter(s))
		return;
	/* Could this response be compressed for some client? Then it varies by Accept-Encoding. */
	if (!(h->status >= 200 && h->status <= 203) ||
	    bst_headers_get(&h->headers, BST_H_CONTENT_RANGE) != NULL ||
	    bst_headers_list_has(&h->headers, BST_H_CACHE_CONTROL, BST_S("no-transform")) ||
	    !type_ok(cfg, &h->headers))
		return;
	const bst_header *ce = bst_headers_get(&h->headers, BST_H_CONTENT_ENCODING);
	if (ce != NULL && !bst_str_ieq(ce->value, BST_S("identity")))
		return;
	if (h->content_length >= 0 && (uint64_t)h->content_length < cfg->min_size)
		return;
	if (own_headers(s, h) != 0)
		return;
	add_vary(h);
	/* This request, this response: */
	const bst_headers *rq = &s->req.head.headers;
	if (end || s->req.head.method == BST_M_HEAD || bst_headers_get(rq, BST_H_RANGE) != NULL ||
	    bst_headers_list_has(rq, BST_H_CACHE_CONTROL, BST_S("no-transform")))
		return;
	if (!cfg->sensitive && (bst_headers_get(rq, BST_H_COOKIE) != NULL ||
				bst_headers_get(rq, BST_H_AUTHORIZATION) != NULL ||
				bst_headers_get(&h->headers, BST_H_SET_COOKIE) != NULL))
		return;
	bst_encoding enc = bst_negotiate_encoding(accept_encoding(s), cfg->encodings);
	if (enc == BST_ENC_IDENTITY || g_active >= cfg->max_concurrent)
		return;
	cz *z = bst_arena_alloc(s->arena, sizeof *z);
	if (z == NULL)
		return;
	memset(z, 0, sizeof *z);
	z->enc = enc;
	z->w = s->worker;
	g_active++;
	if (cz_init(z, cfg) != 0) { /* over the memory budget: identity */
		cz_end(z);
		return;
	}
	const bst_header *et = bst_headers_get(&h->headers, BST_H_ETAG);
	if (et != NULL && et->value.len > 0 && et->value.p[0] == '"') {
		char *w = bst_arena_alloc(s->arena, et->value.len + 2);
		if (w == NULL) {
			cz_end(z);
			return;
		}
		memcpy(w, "W/", 2);
		memcpy(w + 2, et->value.p, et->value.len);
		if (bst_headers_set(&h->headers, BST_S("ETag"), (bst_str){ w, et->value.len + 2 }) != 0) {
			cz_end(z);
			return;
		}
	}
	if (bst_headers_set(&h->headers, BST_S("Content-Encoding"), bst_encoding_name(enc)) != 0) {
		cz_end(z);
		return;
	}
	(void)bst_headers_remove(&h->headers, BST_H_ACCEPT_RANGES);
	h->content_length = -1;
	z->f.ops = &cz_ops;
	bst_stream_add_filter(s, &z->f);
}

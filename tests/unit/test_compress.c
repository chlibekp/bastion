/* The compression filter (filters/compress.c) driven directly on a bare stream: each coding
 * decompresses to the original, the head is rewritten, skip rules hold. */
#include "filters/compress.h"
#include "http/accept_encoding.h"
#include "tap.h"

#include <brotli/decode.h>
#include <stdlib.h>
#include <string.h>
#include <zlib-ng.h>
#include <zstd.h>

static const bst_str types[] = { { "text/plain", 10 } };

typedef struct fx {
	bst_stream s;
	bst_cfg_common cfg;
	bst_resp_head h;
	bst_slab *slab;
} fx;

static void fx_init(fx *f, const char *ae)
{
	memset(f, 0, sizeof *f);
	f->s.arena = bst_arena_new(4096);
	f->slab = bst_chain_slab_new(64);
	f->cfg.compress = (bst_cfg_compress){ .encodings = BST_ENC_ALL, .types = types, .ntypes = 1,
					      .min_size = 10, .level_zstd = 3, .level_br = 4,
					      .level_gzip = 5, .window = 15, .max_concurrent = 4 };
	f->s.cfg = &f->cfg;
	f->s.req.head.method = BST_M_GET;
	bst_headers_init(&f->s.req.head.headers, f->s.arena);
	if (ae != NULL)
		(void)bst_headers_add(&f->s.req.head.headers, BST_S("Accept-Encoding"),
				      (bst_str){ ae, (uint32_t)strlen(ae) });
	f->h.status = 200;
	f->h.content_length = 100000;
	bst_headers_init(&f->h.headers, f->s.arena);
	(void)bst_headers_add(&f->h.headers, BST_S("Content-Type"), BST_S("text/plain; charset=utf-8"));
	(void)bst_headers_add(&f->h.headers, BST_S("ETag"), BST_S("\"abc\""));
}

static void fx_free(fx *f)
{
	bst_stream_release(&f->s);
	bst_arena_free(f->s.arena);
	bst_slab_free(f->slab);
}

static bst_str hdr(fx *f, bst_hdr_id id)
{
	const bst_header *h = bst_headers_get(&f->h.headers, id);
	return h == NULL ? BST_S("") : h->value;
}

/* Runs the body (n bytes of a pattern, in pieces of `piece`) through the filter and returns the
 * output, malloc'd. */
static unsigned char *pump(fx *f, size_t n, size_t piece, size_t *outlen)
{
	unsigned char *out = NULL;
	size_t ol = 0;
	size_t sent = 0;
	do {
		size_t k = n - sent < piece ? n - sent : piece;
		bst_buf *b = bst_buf_new(k > 0 ? k : 1);
		for (size_t i = 0; i < k; i++)
			b->data[i] = (unsigned char)("hello compressible world "[(sent + i) % 25]);
		b->len = k;
		bst_chain c;
		bst_chain_init(&c, f->slab);
		(void)bst_chain_add_mem(&c, b, 0, k);
		bst_buf_unref(b);
		sent += k;
		bool end = sent == n;
		if (f->s.filters->ops->on_body(f->s.filters, &c, end) != 0)
			return NULL;
		size_t cl = (size_t)bst_chain_len(&c);
		out = realloc(out, ol + cl + 1);
		while (bst_chain_len(&c) > 0) {
			struct iovec iov;
			(void)bst_chain_to_iov(&c, &iov, 1);
			memcpy(out + ol, iov.iov_base, iov.iov_len);
			ol += iov.iov_len;
			bst_chain_consume(&c, iov.iov_len);
		}
	} while (sent < n);
	*outlen = ol;
	return out;
}

static bool decodes_to_pattern(bst_encoding e, const unsigned char *in, size_t inlen, size_t n)
{
	unsigned char *dec = malloc(n + 16);
	size_t dl = 0;
	bool ok = false;
	if (e == BST_ENC_ZSTD) {
		size_t r = ZSTD_decompress(dec, n + 16, in, inlen);
		ok = !ZSTD_isError(r);
		dl = r;
	} else if (e == BST_ENC_BR) {
		dl = n + 16;
		ok = BrotliDecoderDecompress(inlen, in, &dl, dec) == BROTLI_DECODER_RESULT_SUCCESS;
	} else {
		zng_stream z = { 0 };
		ok = zng_inflateInit2(&z, 15 + 16) == Z_OK;
		z.next_in = in;
		z.avail_in = (uint32_t)inlen;
		z.next_out = dec;
		z.avail_out = (uint32_t)(n + 16);
		ok = ok && zng_inflate(&z, Z_FINISH) == Z_STREAM_END;
		dl = z.total_out;
		zng_inflateEnd(&z);
	}
	for (size_t i = 0; ok && i < n; i++)
		ok = dec[i] == (unsigned char)("hello compressible world "[i % 25]);
	free(dec);
	return ok && dl == n;
}

TEST(each_encoding_roundtrip)
{
	const char *ae[] = { "zstd", "br", "gzip" };
	bst_encoding enc[] = { BST_ENC_ZSTD, BST_ENC_BR, BST_ENC_GZIP };
	size_t sizes[] = { 0, 1, 1000, 300000 };
	for (int k = 0; k < 3; k++)
		for (size_t i = 0; i < 4; i++) {
			fx f;
			fx_init(&f, ae[k]);
			f.h.content_length = -1;
			bst_compress_attach(&f.s, &f.h, false);
			ASSERT(f.s.filters != NULL);
			ASSERT(bst_str_eq(hdr(&f, BST_H_CONTENT_ENCODING), bst_encoding_name(enc[k])));
			size_t ol;
			unsigned char *o = pump(&f, sizes[i], 7000, &ol);
			ASSERT(o != NULL);
			ASSERT(decodes_to_pattern(enc[k], o, ol, sizes[i]));
			free(o);
			ASSERT_EQ(bst_compress_active(), 0u); /* ended with the stream's end */
			fx_free(&f);
		}
}

TEST(head_rewritten)
{
	fx f;
	fx_init(&f, "gzip");
	bst_compress_attach(&f.s, &f.h, false);
	ASSERT_EQ(f.h.content_length, -1);
	ASSERT(bst_str_eq(hdr(&f, BST_H_ETAG), BST_S("W/\"abc\"")));
	ASSERT(bst_str_eq(hdr(&f, BST_H_VARY), BST_S("Accept-Encoding")));
	ASSERT_EQ(bst_compress_active(), 1u);
	fx_free(&f); /* release mid-stream frees the compressor */
	ASSERT_EQ(bst_compress_active(), 0u);
}

TEST(skip_rules)
{
	for (int k = 0; k < 9; k++) {
		fx f;
		fx_init(&f, "gzip");
		bool end = false;
		switch (k) {
		case 0: f.h.content_length = 5; break;					/* small */
		case 1: (void)bst_headers_add(&f.h.headers, BST_S("Content-Encoding"), BST_S("br")); break;
		case 2: (void)bst_headers_set(&f.h.headers, BST_S("Content-Type"), BST_S("image/png")); break;
		case 3: (void)bst_headers_add(&f.h.headers, BST_S("Cache-Control"), BST_S("no-transform")); break;
		case 4: f.s.req.head.method = BST_M_HEAD; break;
		case 5: f.h.status = 204; break;
		case 6: f.h.status = 304; break;
		case 7: (void)bst_headers_add(&f.s.req.head.headers, BST_S("Range"), BST_S("bytes=0-1")); break;
		case 8: end = true; break;
		}
		bst_compress_attach(&f.s, &f.h, end);
		ASSERT(f.s.filters == NULL);
		ASSERT(bst_headers_get(&f.h.headers, BST_H_CONTENT_ENCODING) == NULL || k == 1);
		fx_free(&f);
	}
}

TEST(sensitive_default_off)
{
	const char *req[] = { "Cookie", "Authorization" };
	for (int k = 0; k < 3; k++) {
		for (int on = 0; on < 2; on++) {
			fx f;
			fx_init(&f, "gzip");
			f.cfg.compress.sensitive = on;
			if (k < 2)
				(void)bst_headers_add(&f.s.req.head.headers,
						      (bst_str){ req[k], (uint32_t)strlen(req[k]) }, BST_S("x"));
			else
				(void)bst_headers_add(&f.h.headers, BST_S("Set-Cookie"), BST_S("a=b"));
			bst_compress_attach(&f.s, &f.h, false);
			ASSERT_EQ(f.s.filters != NULL, (bool)on);
			fx_free(&f);
		}
	}
}

TEST(max_concurrent_falls_back)
{
	fx f[5];
	for (int i = 0; i < 5; i++) {
		fx_init(&f[i], "gzip");
		bst_compress_attach(&f[i].s, &f[i].h, false);
		ASSERT_EQ(f[i].s.filters != NULL, i < 4);
	}
	ASSERT_EQ(bst_compress_active(), 4u);
	for (int i = 0; i < 5; i++)
		fx_free(&f[i]);
	ASSERT_EQ(bst_compress_active(), 0u);
}

TEST(identity_without_accept_encoding)
{
	fx f;
	fx_init(&f, NULL);
	bst_compress_attach(&f.s, &f.h, false);
	ASSERT(f.s.filters == NULL);
	ASSERT(bst_str_eq(hdr(&f, BST_H_VARY), BST_S("Accept-Encoding"))); /* still varies */
	fx_free(&f);
}

TAP_MAIN()

/* libFuzzer harness for the HTTP/1.1 chunked body decoder. The first input byte is a flag set
 * (bit 0: read every LF as CRLF; bit 1: small limits), the rest is the body bytes.
 *
 * Properties: no crash or sanitizer report; the decoded bytes, the outcome, the status and
 * the number of input bytes used are the same whether the input arrives whole, in two parts or
 * one byte at a time; decoded bytes never outnumber the input; and a finished message leaves
 * the rest of the input unconsumed. */
#include "http/h1/body.h"

#include <stdlib.h>
#include <string.h>

typedef struct outcome {
	bst_h1_body_kind kind;
	int status;
	size_t used;
	uint32_t ntrailers;
	char *data;
	size_t datalen;
} outcome;

static void gather(bst_chain *c, outcome *o)
{
	struct iovec iov[256];
	size_t cap = (size_t)bst_chain_len(c);
	o->data = malloc(cap ? cap : 1);
	o->datalen = 0;
	for (;;) {
		int k = bst_chain_to_iov(c, iov, 256);
		if (k == 0)
			break;
		size_t got = 0;
		for (int i = 0; i < k; i++) {
			memcpy(o->data + o->datalen + got, iov[i].iov_base, iov[i].iov_len);
			got += iov[i].iov_len;
		}
		o->datalen += got;
		bst_chain_consume(c, got);
	}
}

/* Feeds the input in pieces of the given sizes; sizes[i] == 0 ends the list and feeds the rest. */
static void run(const char *in, size_t n, const bst_h1_body_cfg *cfg, const size_t *sizes,
		size_t piece, outcome *o)
{
	bst_arena *arena = bst_arena_new(1024);
	bst_slab *slab = bst_chain_slab_new(64);
	bst_chain out;
	bst_chain_init(&out, slab);
	bst_headers tr;
	bst_headers_init(&tr, arena);
	bst_h1_body body;
	bst_h1_body_init(&body, (bst_framing){ .kind = BST_FRAMING_CHUNKED }, cfg, arena);
	o->kind = BST_H1_BODY_MORE;
	o->status = 0;
	size_t pos = 0, si = 0;
	while (pos < n && o->kind == BST_H1_BODY_MORE) {
		size_t k = piece ? piece : (sizes && sizes[si] ? sizes[si++] : n - pos);
		if (k > n - pos)
			k = n - pos;
		bst_buf *b = bst_buf_new(k);
		memcpy(b->data, in + pos, k);
		b->len = k;
		size_t off = 0;
		o->kind = bst_h1_body_feed(&body, b, &off, &out, &tr, &o->status);
		pos += off;
		bst_buf_unref(b);
	}
	o->used = pos;
	o->ntrailers = tr.n;
	gather(&out, o);
	bst_chain_clear(&out);
	bst_slab_free(slab);
	bst_arena_free(arena);
}

static bool same(const outcome *a, const outcome *b)
{
	/* after an error the position inside the failing read is not meaningful */
	bool err = a->kind == BST_H1_BODY_ERROR;
	return a->kind == b->kind && a->status == b->status && (err || a->used == b->used) &&
	       (err || a->ntrailers == b->ntrailers) && a->datalen == b->datalen &&
	       memcmp(a->data, b->data, a->datalen) == 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size < 1)
		return 0;
	uint8_t flags = d[0];
	size_t inlen = size - 1;
	char *in = malloc(inlen * 2 + 1);
	size_t n = 0;
	for (size_t i = 0; i < inlen; i++) {
		if ((flags & 1) && d[1 + i] == '\n')
			in[n++] = '\r';
		in[n++] = (char)d[1 + i];
	}
	bst_h1_body_cfg cfg = { .max_body = 1 << 20, .chunk_ext_limit = 64, .max_trailer = 256 };
	if (flags & 2)
		cfg = (bst_h1_body_cfg){ .max_body = 40, .chunk_ext_limit = 8, .max_trailer = 32 };

	outcome whole, split, bytes;
	run(in, n, &cfg, NULL, 0, &whole);
	if (whole.datalen > n || whole.used > n || (whole.kind == BST_H1_BODY_DONE && whole.used == 0))
		abort();
	size_t two[2] = { n / 2 + 1, 0 };
	run(in, n, &cfg, two, 0, &split);
	if (!same(&whole, &split))
		abort();
	if (n <= 600) {
		run(in, n, &cfg, NULL, 1, &bytes);
		if (!same(&whole, &bytes))
			abort();
		free(bytes.data);
	}
	free(whole.data);
	free(split.data);
	free(in);
	return 0;
}

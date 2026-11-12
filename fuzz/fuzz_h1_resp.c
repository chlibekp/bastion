/* libFuzzer harness for the upstream response reader (http/h1/resp_parser.c through
 * proxy/client_h1.c). Properties: no crash or hang; the answer never depends on how the bytes are
 * split (the input is read once whole and once in pieces cut where the first byte says, and both
 * runs end in the same event with the same body length); a head that parses never holds a CR or
 * LF in a value. Input: one byte of split stride, one byte of flags (bit 0: HEAD request), then
 * the response bytes. */
#include "http/token.h"
#include "proxy/client_h1.h"

#include <stdlib.h>
#include <string.h>

typedef struct run {
	bst_upc_ev ev;
	uint64_t body;
	int status;
} run;

static run read_in(const uint8_t *d, size_t n, size_t stride, bool head)
{
	bst_arena *a = bst_arena_new(1 << 14);
	bst_slab *slab = bst_chain_slab_new(64);
	bst_chain out;
	bst_chain_init(&out, slab);
	bst_h1_body_cfg bc = { .chunk_ext_limit = 256, .max_trailer = 1024 };
	bst_h1_client c;
	bst_h1_client_init(&c, a, 4096, head, &bc);
	run r = { BST_UPC_MORE, 0, 0 };
	for (size_t at = 0; at < n && r.ev != BST_UPC_ERROR && r.ev != BST_UPC_DONE; at += stride) {
		size_t len = n - at < stride ? n - at : stride;
		bst_buf *b = bst_buf_new(len);
		memcpy(b->data, d + at, len);
		b->len = len;
		size_t off = 0;
		do {
			r.ev = bst_h1_client_feed(&c, b, &off, &out);
			if (r.ev == BST_UPC_HEAD || r.ev == BST_UPC_INTERIM) {
				for (uint32_t i = 0; i < c.head.headers.n; i++)
					if (!bst_is_field_value_clean(c.head.headers.v[i].value))
						abort();
				if (r.ev == BST_UPC_HEAD)
					r.status = c.head.status;
			}
		} while (r.ev == BST_UPC_HEAD || r.ev == BST_UPC_INTERIM || r.ev == BST_UPC_BODY);
		r.body = bst_chain_len(&out);
		bst_chain_clear(&out);
		bst_buf_unref(b);
	}
	if (r.ev == BST_UPC_MORE)
		r.ev = bst_h1_client_eof(&c);
	bst_h1_client_free(&c);
	bst_slab_free(slab);
	bst_arena_free(a);
	return r;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t len)
{
	if (len < 2)
		return 0;
	size_t stride = 1 + d[0] % 31;
	bool head = d[1] & 1;
	d += 2;
	len -= 2;
	if (len > 8192)
		len = 8192;
	run whole = read_in(d, len, len ? len : 1, head);
	run cut = read_in(d, len, stride, head);
	if (whole.ev != cut.ev || whole.status != cut.status)
		abort();
	return 0;
}

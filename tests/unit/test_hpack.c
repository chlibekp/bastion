/* Huffman and HPACK: RFC 7541 Appendix C vectors both ways, and the limits that keep a hostile
 * block from growing memory. */
#include "http/h2/hpack.h"
#include "http/h2/huffman.h"
#include "tap.h"

#include <stdlib.h>
#include <string.h>

static size_t unhex(const char *hex, uint8_t *out)
{
	size_t n = 0;
	for (const char *p = hex; *p; p++) {
		if (*p == ' ')
			continue;
		unsigned v = (unsigned)(*p <= '9' ? *p - '0' : *p - 'a' + 10);
		unsigned w = (unsigned)(p[1] <= '9' ? p[1] - '0' : p[1] - 'a' + 10);
		out[n++] = (uint8_t)(v << 4 | w);
		p++;
	}
	return n;
}

static bool hex_eq(const bst_h2_wr *w, const char *hex)
{
	uint8_t want[512];
	size_t n = unhex(hex, want);
	return n == w->len && memcmp(want, w->p, n) == 0;
}

static const bst_hpack_limits LIM = { .max_header_list_size = 16384 };

static int decode_hex(bst_hpack_dec *d, const char *hex, bst_arena *a, bst_headers *h)
{
	uint8_t buf[512];
	size_t n = unhex(hex, buf);
	bst_headers_init(h, a);
	return bst_hpack_decode(d, buf, n, a, h, &LIM);
}

static bool has(const bst_headers *h, uint32_t i, const char *n, const char *v)
{
	return i < h->n && bst_str_eq(h->v[i].name, (bst_str){ n, (uint32_t)strlen(n) }) &&
	       bst_str_eq(h->v[i].value, (bst_str){ v, (uint32_t)strlen(v) });
}

static void add(bst_headers *h, const char *n, const char *v)
{
	(void)bst_headers_add(h, (bst_str){ n, (uint32_t)strlen(n) }, (bst_str){ v, (uint32_t)strlen(v) });
}

/* ---- Appendix C.1 and C.2 ---- */

TEST(rfc7541_c1_integers)
{
	bst_h2_wr w = { 0 };
	ASSERT_EQ(bst_hpack_int_encode(&w, 0, 5, 10), 0);
	ASSERT(hex_eq(&w, "0a"));
	w.len = 0;
	ASSERT_EQ(bst_hpack_int_encode(&w, 0, 5, 1337), 0);
	ASSERT(hex_eq(&w, "1f9a0a"));
	w.len = 0;
	ASSERT_EQ(bst_hpack_int_encode(&w, 0, 8, 42), 0);
	ASSERT(hex_eq(&w, "2a"));
	const uint8_t *p = w.p;
	uint32_t v;
	ASSERT_EQ(bst_hpack_int_decode(&p, w.p + w.len, 8, &v), 0);
	ASSERT_EQ(v, 42);
	bst_h2_wr_free(&w);
}

TEST(rfc7541_c2_literals)
{
	bst_arena *a = bst_arena_new(4096);
	bst_hpack_dec d;
	bst_headers h;
	bst_hpack_dec_init(&d, 4096);
	ASSERT_EQ(decode_hex(&d, "400a637573746f6d2d6b6579 0d637573746f6d2d686561646572", a, &h), 0);
	ASSERT(has(&h, 0, "custom-key", "custom-header"));
	ASSERT_EQ(bst_hpack_table_size(&d.t), 55);
	ASSERT_EQ(decode_hex(&d, "040c2f73616d706c652f70617468", a, &h), 0);
	ASSERT(has(&h, 0, ":path", "/sample/path"));
	ASSERT_EQ(bst_hpack_table_count(&d.t), 1); /* not indexed */
	ASSERT_EQ(decode_hex(&d, "100870617373776f726406736563726574", a, &h), 0);
	ASSERT(has(&h, 0, "password", "secret"));
	ASSERT_EQ(bst_hpack_table_count(&d.t), 1);
	ASSERT_EQ(decode_hex(&d, "82", a, &h), 0);
	ASSERT(has(&h, 0, ":method", "GET"));
	bst_hpack_dec_free(&d);
	bst_arena_free(a);
}

/* ---- Appendix C.3 to C.6: decode, then encode with the example's own policy ---- */

typedef struct vec {
	const char *hex;
	size_t nfields;
	const char *f[8][2];
	size_t table_size;
} vec;

static const vec REQ_RAW[] = {
	{ "828684410f7777772e6578616d706c652e636f6d", 4,
	  { { ":method", "GET" }, { ":scheme", "http" }, { ":path", "/" }, { ":authority", "www.example.com" } }, 57 },
	{ "828684be58086e6f2d6361636865", 5,
	  { { ":method", "GET" }, { ":scheme", "http" }, { ":path", "/" }, { ":authority", "www.example.com" },
	    { "cache-control", "no-cache" } }, 110 },
	{ "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565", 5,
	  { { ":method", "GET" }, { ":scheme", "https" }, { ":path", "/index.html" },
	    { ":authority", "www.example.com" }, { "custom-key", "custom-value" } }, 164 },
};
static const vec REQ_HUFF[] = {
	{ "828684418cf1e3c2e5f23a6ba0ab90f4ff", 4,
	  { { ":method", "GET" }, { ":scheme", "http" }, { ":path", "/" }, { ":authority", "www.example.com" } }, 57 },
	{ "828684be5886a8eb10649cbf", 5,
	  { { ":method", "GET" }, { ":scheme", "http" }, { ":path", "/" }, { ":authority", "www.example.com" },
	    { "cache-control", "no-cache" } }, 110 },
	{ "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf", 5,
	  { { ":method", "GET" }, { ":scheme", "https" }, { ":path", "/index.html" },
	    { ":authority", "www.example.com" }, { "custom-key", "custom-value" } }, 164 },
};
static const vec RESP_RAW[] = {
	{ "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d", 4,
	  { { ":status", "302" }, { "cache-control", "private" }, { "date", "Mon, 21 Oct 2013 20:13:21 GMT" },
	    { "location", "https://www.example.com" } }, 222 },
	{ "4803333037c1c0bf", 4,
	  { { ":status", "307" }, { "cache-control", "private" }, { "date", "Mon, 21 Oct 2013 20:13:21 GMT" },
	    { "location", "https://www.example.com" } }, 222 },
	{ "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31", 6,
	  { { ":status", "200" }, { "cache-control", "private" }, { "date", "Mon, 21 Oct 2013 20:13:22 GMT" },
	    { "location", "https://www.example.com" }, { "content-encoding", "gzip" },
	    { "set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" } }, 215 },
};
static const vec RESP_HUFF[] = {
	{ "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3", 4,
	  { { ":status", "302" }, { "cache-control", "private" }, { "date", "Mon, 21 Oct 2013 20:13:21 GMT" },
	    { "location", "https://www.example.com" } }, 222 },
	{ "4883640effc1c0bf", 4,
	  { { ":status", "307" }, { "cache-control", "private" }, { "date", "Mon, 21 Oct 2013 20:13:21 GMT" },
	    { "location", "https://www.example.com" } }, 222 },
	{ "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007", 6,
	  { { ":status", "200" }, { "cache-control", "private" }, { "date", "Mon, 21 Oct 2013 20:13:22 GMT" },
	    { "location", "https://www.example.com" }, { "content-encoding", "gzip" },
	    { "set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" } }, 215 },
};

static void run_series(const vec *v, size_t n, uint32_t table, bst_hpack_policy pol, bool *ok)
{
	bst_arena *a = bst_arena_new(8192);
	bst_hpack_dec d;
	bst_hpack_enc e;
	bst_hpack_dec_init(&d, table);
	bst_hpack_enc_init(&e, table);
	e.policy = pol;
	*ok = true;
	for (size_t i = 0; i < n && *ok; i++) {
		bst_headers h;
		/* the example's blocks carry no size update: start the decoder at the example's size */
		if (i == 0 && table != 4096) {
			d.t.max = table;
			e.t.max = table;
			e.pending = false;
		}
		int rc = decode_hex(&d, v[i].hex, a, &h);
		*ok = rc == 0 && h.n == v[i].nfields && bst_hpack_table_size(&d.t) == v[i].table_size;
		for (size_t k = 0; *ok && k < v[i].nfields; k++)
			*ok = has(&h, (uint32_t)k, v[i].f[k][0], v[i].f[k][1]);
		if (!*ok) {
			fprintf(stderr, "# vector %zu: decode rc %d, %u fields, table %zu\n", i, rc, h.n,
				bst_hpack_table_size(&d.t));
			break;
		}
		bst_headers in;
		bst_headers_init(&in, a);
		for (size_t k = 0; k < v[i].nfields; k++)
			add(&in, v[i].f[k][0], v[i].f[k][1]);
		bst_h2_wr w = { 0 };
		*ok = bst_hpack_encode(&e, &in, &w) == 0 && hex_eq(&w, v[i].hex) &&
		      bst_hpack_table_size(&e.t) == v[i].table_size;
		if (!*ok) {
			fprintf(stderr, "# vector %zu: encoded %zu bytes, table %zu:", i, w.len,
				bst_hpack_table_size(&e.t));
			for (size_t k = 0; k < w.len; k++)
				fprintf(stderr, " %02x", w.p[k]);
			fprintf(stderr, "\n");
		}
		bst_h2_wr_free(&w);
	}
	bst_hpack_dec_free(&d);
	bst_hpack_enc_free(&e);
	bst_arena_free(a);
}

TEST(rfc7541_c_vectors)
{
	bool ok;
	run_series(REQ_RAW, 3, 4096, BST_HPACK_POLICY_INDEX_ALL_RAW, &ok);
	ASSERT(ok); /* C.3 */
	run_series(REQ_HUFF, 3, 4096, BST_HPACK_POLICY_INDEX_ALL, &ok);
	ASSERT(ok); /* C.4 */
	run_series(RESP_RAW, 3, 256, BST_HPACK_POLICY_INDEX_ALL_RAW, &ok);
	ASSERT(ok); /* C.5, with evictions */
	run_series(RESP_HUFF, 3, 256, BST_HPACK_POLICY_INDEX_ALL, &ok);
	ASSERT(ok); /* C.6 */
}

/* ---- Huffman ---- */

TEST(huffman_all_symbols)
{
	uint8_t all[256], enc[1024], dec[512];
	for (int i = 0; i < 256; i++) {
		all[i] = (uint8_t)i;
		size_t n = bst_huff_encoded_len(all + i, 1);
		ASSERT_EQ(bst_huff_encode(all + i, 1, enc), n);
		ASSERT_EQ(bst_huff_decode(enc, n, dec, sizeof dec), 1);
		ASSERT_EQ(dec[0], i);
	}
	size_t n = bst_huff_encoded_len(all, 256);
	ASSERT(n <= sizeof enc);
	ASSERT_EQ(bst_huff_encode(all, 256, enc), n);
	ASSERT_EQ(bst_huff_decode(enc, n, dec, sizeof dec), 256);
	ASSERT(memcmp(dec, all, 256) == 0);
	ASSERT_EQ(bst_huff_decode(enc, n, dec, 255), BST_HUFF_TOO_BIG);
	/* the example strings of Appendix C.4 */
	uint8_t want[32];
	size_t wn = unhex("f1e3c2e5f23a6ba0ab90f4ff", want);
	ASSERT_EQ(bst_huff_encoded_len((const uint8_t *)"www.example.com", 15), wn);
	bst_huff_encode((const uint8_t *)"www.example.com", 15, enc);
	ASSERT(memcmp(enc, want, wn) == 0);
}

TEST(huffman_bad_padding)
{
	uint8_t out[64];
	/* 'a' is 00011: padded with 111 is legal, with zeros is not */
	ASSERT_EQ(bst_huff_decode((const uint8_t *)"\x1f", 1, out, sizeof out), 1);
	ASSERT_EQ(bst_huff_decode((const uint8_t *)"\x18", 1, out, sizeof out), BST_HUFF_ERR);
	/* a whole byte of padding after 'a' (more than 7 bits) */
	ASSERT_EQ(bst_huff_decode((const uint8_t *)"\x1f\xff", 2, out, sizeof out), BST_HUFF_ERR);
	/* the EOS symbol itself (30 ones) */
	ASSERT_EQ(bst_huff_decode((const uint8_t *)"\xff\xff\xff\xff", 4, out, sizeof out), BST_HUFF_ERR);
	/* ones that stop in the middle of a longer code are padding only up to 7 bits */
	ASSERT_EQ(bst_huff_decode((const uint8_t *)"\xff", 1, out, sizeof out), BST_HUFF_ERR);
	ASSERT_EQ(bst_huff_decode((const uint8_t *)"", 0, out, sizeof out), 0);
}

/* ---- integers ---- */

TEST(int_overflow)
{
	uint32_t v;
	uint8_t big[] = { 0x1f, 0xff, 0xff, 0xff, 0xff, 0x0f }; /* 2^32 - 1 + 31 */
	const uint8_t *p = big;
	ASSERT_EQ(bst_hpack_int_decode(&p, big + sizeof big, 5, &v), -1);
	uint8_t ok[] = { 0x1f, 0xe0, 0xff, 0xff, 0xff, 0x0f }; /* 2^32 - 1 exactly */
	p = ok;
	ASSERT_EQ(bst_hpack_int_decode(&p, ok + sizeof ok, 5, &v), 0);
	ASSERT_EQ(v, UINT32_MAX);
	uint8_t wrap[] = { 0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 }; /* zeros that would shift out */
	p = wrap;
	ASSERT_EQ(bst_hpack_int_decode(&p, wrap + sizeof wrap, 5, &v), -1);
	uint8_t cut[] = { 0x1f, 0x80 }; /* continues past the end */
	p = cut;
	ASSERT_EQ(bst_hpack_int_decode(&p, cut + sizeof cut, 5, &v), -1);
	bst_arena *a = bst_arena_new(4096);
	bst_hpack_dec d;
	bst_headers h;
	bst_hpack_dec_init(&d, 4096);
	ASSERT_EQ(decode_hex(&d, "ffffffffff0f", a, &h), BST_HPACK_ERR); /* an indexed field, 2^32 + 127 */
	bst_hpack_dec_free(&d);
	bst_arena_free(a);
}

/* ---- the table ---- */

TEST(table_eviction)
{
	bst_arena *a = bst_arena_new(4096);
	bst_hpack_dec d;
	bst_headers h;
	bst_hpack_dec_init(&d, 4096);
	ASSERT_EQ(decode_hex(&d, "3f e1 01", a, &h), 0); /* size update to 256 (31 + 225) */
	ASSERT_EQ(d.t.max, 256);
	/* entries of 32 + 3 + 3 = 38 bytes: six fit in 256, so eight inserts evict the two oldest */
	for (int i = 0; i < 8; i++) {
		uint8_t b[16];
		size_t n = 0;
		b[n++] = 0x40;
		b[n++] = 3;
		memcpy(b + n, "key", 3), n += 3;
		b[n++] = 3;
		b[n++] = 'v';
		b[n++] = 'a';
		b[n++] = (uint8_t)('0' + i);
		bst_headers_init(&h, a);
		ASSERT_EQ(bst_hpack_decode(&d, b, n, a, &h, &LIM), 0);
	}
	ASSERT_EQ(bst_hpack_table_count(&d.t), 256 / 38); /* 6 entries of 38 bytes */
	ASSERT_EQ(bst_hpack_table_size(&d.t), (256 / 38) * 38);
	/* the newest entry is index 62 and carries the last value */
	ASSERT_EQ(decode_hex(&d, "be", a, &h), 0);
	ASSERT(has(&h, 0, "key", "va7"));
	/* an entry bigger than the table empties it and is not added */
	uint8_t big[300];
	size_t n = 0;
	big[n++] = 0x40;
	big[n++] = 1;
	big[n++] = 'k';
	big[n++] = 0x7f; /* a raw value of 127 + 100 = 227 bytes: the entry is 260, the table 256 */
	big[n++] = 100;
	memset(big + n, 'z', 227);
	n += 227;
	bst_headers_init(&h, a);
	ASSERT_EQ(bst_hpack_decode(&d, big, n, a, &h, &LIM), 0);
	ASSERT_EQ(h.n, 1);
	ASSERT_EQ(bst_hpack_table_count(&d.t), 0);
	ASSERT_EQ(bst_hpack_table_size(&d.t), 0);
	bst_hpack_dec_free(&d);
	bst_arena_free(a);
}

TEST(dyn_table_update_rules)
{
	bst_arena *a = bst_arena_new(4096);
	bst_hpack_dec d;
	bst_headers h;
	bst_hpack_dec_init(&d, 1000);
	ASSERT_EQ(decode_hex(&d, "3fe907", a, &h), BST_HPACK_ERR); /* 31 + 105 + 7 * 128 = 1032 > 1000 */
	ASSERT_EQ(decode_hex(&d, "3fc906", a, &h), 0);		    /* 31 + 73 + 6 * 128 = 872 */
	ASSERT_EQ(d.t.max, 872);
	/* an update after a field is not at the start of the block */
	ASSERT_EQ(decode_hex(&d, "82 20", a, &h), BST_HPACK_ERR);
	/* two updates at the start are fine (the smallest, then the final) */
	ASSERT_EQ(decode_hex(&d, "20 3fe101 82", a, &h), 0);
	ASSERT_EQ(d.t.max, 256);
	ASSERT_EQ(h.n, 1);
	bst_hpack_dec_free(&d);
	bst_arena_free(a);
}

TEST(index_zero_and_past_end)
{
	bst_arena *a = bst_arena_new(4096);
	bst_hpack_dec d;
	bst_headers h;
	bst_hpack_dec_init(&d, 4096);
	ASSERT_EQ(decode_hex(&d, "80", a, &h), BST_HPACK_ERR);   /* index 0 */
	ASSERT_EQ(decode_hex(&d, "be", a, &h), BST_HPACK_ERR);   /* 62, with an empty table */
	ASSERT_EQ(decode_hex(&d, "ff7f", a, &h), BST_HPACK_ERR); /* far past the end */
	ASSERT_EQ(decode_hex(&d, "7e 01 61", a, &h), BST_HPACK_ERR); /* name index 62 in a literal */
	ASSERT_EQ(decode_hex(&d, "40 05 61", a, &h), BST_HPACK_ERR); /* a name longer than the input */
	ASSERT_EQ(decode_hex(&d, "40 01 61", a, &h), BST_HPACK_ERR); /* no value */
	ASSERT_EQ(decode_hex(&d, "40 81 ff 01 61", a, &h), BST_HPACK_ERR); /* bad huffman padding */
	bst_hpack_dec_free(&d);
	bst_arena_free(a);
}

/* A literal with incremental indexing: a name and a value of vlen bytes of fill (a Huffman string
 * when huff). Returns the block length. */
static size_t lit_block(uint8_t *out, const char *name, size_t vlen, int fill, bool huff)
{
	bst_h2_wr w = { 0 };
	size_t nl = strlen(name);
	(void)bst_h2_wr_reserve(&w, 16 + nl);
	w.p[w.len++] = 0x40;
	(void)bst_hpack_int_encode(&w, 0, 7, (uint32_t)nl);
	memcpy(w.p + w.len, name, nl);
	w.len += nl;
	(void)bst_hpack_int_encode(&w, huff ? 0x80 : 0, 7, (uint32_t)vlen);
	memcpy(out, w.p, w.len);
	size_t n = w.len;
	bst_h2_wr_free(&w);
	memset(out + n, fill, vlen);
	return n + vlen;
}

TEST(decoded_size_limit)
{
	bst_arena *a = bst_arena_new(4096);
	bst_hpack_dec d;
	bst_headers h;
	bst_hpack_dec_init(&d, 4096);
	/* put one 3000-byte value in the table ... */
	uint8_t blk[5000];
	size_t n = lit_block(blk, "x", 3000, 'v', false);
	bst_headers_init(&h, a);
	ASSERT_EQ(bst_hpack_decode(&d, blk, n, a, &h, &LIM), 0);
	ASSERT_EQ(bst_hpack_table_count(&d.t), 1);
	/* ... then refer to it 4096 times in a 4 KiB block: 12 MB of headers if it were honoured */
	uint8_t bomb[4096];
	memset(bomb, 0xbe, sizeof bomb);
	bst_arena *a2 = bst_arena_new(4096);
	bst_headers_init(&h, a2);
	ASSERT_EQ(bst_hpack_decode(&d, bomb, sizeof bomb, a2, &h, &LIM), BST_HPACK_TOO_LARGE);
	ASSERT(h.n <= 16384 / 3000 + 1);
	ASSERT(bst_arena_mapped(a2) < 128 * 1024);
	/* a string that claims far more bytes than the block has is malformed, not allocated */
	const uint8_t hb[] = { 0x40, 1, 'x', 0xff, 0xff, 0x7f };
	size_t hn = sizeof hb;
	bst_arena_free(a2);
	a2 = bst_arena_new(4096);
	bst_headers_init(&h, a2);
	ASSERT_EQ(bst_hpack_decode(&d, hb, hn, a2, &h, &LIM), BST_HPACK_ERR);
	bst_arena_free(a2);
	bst_hpack_dec_free(&d);
	bst_arena_free(a);
}

TEST(huffman_expansion_bounded)
{
	/* 8000 bytes of the 5-bit code for '0': 12800 decoded bytes against a 1 KiB list */
	static uint8_t blk[8100];
	size_t n = lit_block(blk, "x", 8000, 0, true); /* zero bits are the code of '0', over and over */
	bst_arena *a = bst_arena_new(4096);
	bst_hpack_dec d;
	bst_headers h;
	bst_hpack_dec_init(&d, 4096);
	bst_headers_init(&h, a);
	bst_hpack_limits lim = { .max_header_list_size = 1024 };
	ASSERT_EQ(bst_hpack_decode(&d, blk, n, a, &h, &lim), BST_HPACK_TOO_LARGE);
	ASSERT(bst_arena_mapped(a) < 32 * 1024);
	bst_hpack_dec_free(&d);
	bst_arena_free(a);
}

/* ---- the encoder's policy ---- */

TEST(encoder_policy_and_roundtrip)
{
	bst_arena *a = bst_arena_new(8192);
	bst_hpack_enc e;
	bst_hpack_dec d;
	bst_hpack_enc_init(&e, 4096);
	bst_hpack_dec_init(&d, 4096);
	bst_headers in, out;
	bst_headers_init(&in, a);
	add(&in, ":status", "200");
	add(&in, "Server", "bastion");
	add(&in, "content-type", "text/html");
	add(&in, "date", "Sun, 06 Nov 1994 08:49:37 GMT");
	add(&in, "content-length", "1234");
	add(&in, "set-cookie", "sid=secret");
	bst_h2_wr w = { 0 };
	ASSERT_EQ(bst_hpack_encode(&e, &in, &w), 0);
	ASSERT_EQ(w.p[0], 0x88); /* :status 200 is the static index 8 */
	/* server and content-type enter the table; date, content-length and set-cookie do not */
	ASSERT_EQ(bst_hpack_table_count(&e.t), 2);
	bool never = false;
	for (size_t i = 0; i + 1 < w.len; i++) /* the set-cookie literal: never indexed, name index 55 */
		if (w.p[i] == 0x1f && w.p[i + 1] == 0x28)
			never = true;
	ASSERT(never);
	bst_headers_init(&out, a);
	ASSERT_EQ(bst_hpack_decode(&d, w.p, w.len, a, &out, &LIM), 0);
	ASSERT_EQ(out.n, 6);
	ASSERT(has(&out, 1, "server", "bastion")); /* lower-cased */
	ASSERT(has(&out, 5, "set-cookie", "sid=secret"));
	ASSERT_EQ(bst_hpack_table_count(&d.t), 2);
	/* the second response is shorter: the repeated fields are single bytes */
	size_t first = w.len;
	w.len = 0;
	ASSERT_EQ(bst_hpack_encode(&e, &in, &w), 0);
	ASSERT(w.len < first);
	bst_headers_init(&out, a);
	ASSERT_EQ(bst_hpack_decode(&d, w.p, w.len, a, &out, &LIM), 0);
	ASSERT_EQ(out.n, 6);
	/* a table size change opens the next block with an update */
	bst_hpack_enc_set_max(&e, 0);
	w.len = 0;
	ASSERT_EQ(bst_hpack_encode(&e, &in, &w), 0);
	ASSERT_EQ(w.p[0], 0x20);
	ASSERT_EQ(bst_hpack_table_count(&e.t), 0);
	bst_headers_init(&out, a);
	ASSERT_EQ(bst_hpack_decode(&d, w.p, w.len, a, &out, &LIM), 0);
	ASSERT_EQ(bst_hpack_table_count(&d.t), 0);
	bst_h2_wr_free(&w);
	bst_hpack_enc_free(&e);
	bst_hpack_dec_free(&d);
	bst_arena_free(a);
}

TAP_MAIN()

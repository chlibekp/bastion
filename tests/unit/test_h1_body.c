#include "http/h1/body.h"
#include "tap.h"

#include <stdlib.h>

static bst_h1_body_cfg cfg(void)
{
	return (bst_h1_body_cfg){ .max_body = 1 << 20, .chunk_ext_limit = 64, .max_trailer = 256 };
}

typedef struct run {
	bst_arena *arena;
	bst_slab *slab;
	bst_chain out;
	bst_headers trailers;
	bst_h1_body b;
	char data[4096];
	size_t datalen;
	size_t used; /* input bytes up to the end of the message, once DONE */
	int status;
	bst_h1_body_kind kind;
} run;

static void flatten(run *r)
{
	struct iovec iov[64];
	int n = bst_chain_to_iov(&r->out, iov, 64);
	r->datalen = 0;
	for (int i = 0; i < n; i++) {
		memcpy(r->data + r->datalen, iov[i].iov_base, iov[i].iov_len);
		r->datalen += iov[i].iov_len;
	}
}

static void run_init(run *r, bst_framing f, bst_h1_body_cfg c)
{
	memset(r, 0, sizeof *r);
	r->arena = bst_arena_new(1024);
	r->slab = bst_chain_slab_new(64);
	bst_chain_init(&r->out, r->slab);
	bst_headers_init(&r->trailers, r->arena);
	bst_h1_body_init(&r->b, f, &c, r->arena);
	r->kind = BST_H1_BODY_MORE;
}

static void run_free(run *r)
{
	bst_chain_clear(&r->out);
	bst_slab_free(r->slab);
	bst_arena_free(r->arena);
}

/* Feeds in in pieces of `piece` bytes (0 = all at once), each in its own buffer. */
static void feed(run *r, const char *in, size_t len, size_t piece)
{
	size_t pos = 0;
	if (piece == 0)
		piece = len ? len : 1;
	while (pos < len && r->kind == BST_H1_BODY_MORE) {
		size_t k = len - pos < piece ? len - pos : piece;
		bst_buf *b = bst_buf_new(k);
		memcpy(b->data, in + pos, k);
		b->len = k;
		size_t off = 0;
		r->kind = bst_h1_body_feed(&r->b, b, &off, &r->out, &r->trailers, &r->status);
		pos += off;
		bst_buf_unref(b);
	}
	r->used = pos;
	flatten(r);
}

#define FEED(r, lit) feed((r), (lit), sizeof(lit) - 1, 0)

static const bst_framing chunked = { .kind = BST_FRAMING_CHUNKED };

TEST(length_body)
{
	run r;
	run_init(&r, (bst_framing){ .kind = BST_FRAMING_LENGTH, .length = 11 }, cfg());
	FEED(&r, "hello world and more");
	ASSERT_EQ(r.kind, BST_H1_BODY_DONE);
	ASSERT_EQ(r.used, 11);
	ASSERT_EQ(r.datalen, 11);
	ASSERT(memcmp(r.data, "hello world", 11) == 0);
	run_free(&r);
	/* in pieces, ends exactly at the length */
	run_init(&r, (bst_framing){ .kind = BST_FRAMING_LENGTH, .length = 11 }, cfg());
	feed(&r, "hello world", 11, 3);
	ASSERT_EQ(r.kind, BST_H1_BODY_DONE);
	ASSERT_EQ(r.datalen, 11);
	run_free(&r);
	run_init(&r, (bst_framing){ .kind = BST_FRAMING_LENGTH, .length = 11 }, cfg());
	FEED(&r, "hello");
	ASSERT_EQ(r.kind, BST_H1_BODY_MORE);
	run_free(&r);
}

TEST(no_body)
{
	run r;
	run_init(&r, (bst_framing){ .kind = BST_FRAMING_NONE }, cfg());
	bst_buf *b = bst_buf_new(4);
	memcpy(b->data, "next", 4);
	b->len = 4;
	size_t off = 0;
	ASSERT_EQ(bst_h1_body_feed(&r.b, b, &off, &r.out, NULL, &r.status), BST_H1_BODY_DONE);
	ASSERT_EQ(off, 0); /* nothing of the next request is touched */
	bst_buf_unref(b);
	run_free(&r);
}

#define CHUNKED_MSG "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n"

TEST(chunk_splits)
{
	const char msg[] = CHUNKED_MSG;
	for (size_t piece = 1; piece <= sizeof msg - 1; piece++) {
		run r;
		run_init(&r, chunked, cfg());
		feed(&r, msg, sizeof msg - 1, piece);
		ASSERT_EQ(r.kind, BST_H1_BODY_DONE);
		ASSERT_EQ(r.used, sizeof msg - 1);
		ASSERT_EQ(r.datalen, 11);
		ASSERT(memcmp(r.data, "hello world", 11) == 0);
		run_free(&r);
	}
	/* two halves at every cut */
	for (size_t cut = 0; cut <= sizeof msg - 1; cut++) {
		run r;
		run_init(&r, chunked, cfg());
		feed(&r, msg, cut, 0);
		if (r.kind == BST_H1_BODY_MORE)
			feed(&r, msg + cut, sizeof msg - 1 - cut, 0);
		ASSERT_EQ(r.kind, BST_H1_BODY_DONE);
		run_free(&r);
	}
}

TEST(chunk_size_overflow)
{
	run r;
	run_init(&r, chunked, cfg());
	FEED(&r, "FFFFFFFFFFFFFFFFF\r\n");
	ASSERT_EQ(r.kind, BST_H1_BODY_ERROR);
	ASSERT_EQ(r.status, 400);
	run_free(&r);
	/* sixteen digits fit in 64 bits, and are then refused as too large rather than wrapped */
	run_init(&r, chunked, cfg());
	FEED(&r, "FFFFFFFFFFFFFFFF\r\n");
	ASSERT_EQ(r.kind, BST_H1_BODY_ERROR);
	ASSERT_EQ(r.status, 413);
	run_free(&r);
	run_init(&r, chunked, cfg());
	FEED(&r, "\r\n"); /* no digit */
	ASSERT_EQ(r.status, 400);
	run_free(&r);
	run_init(&r, chunked, cfg());
	FEED(&r, "-5\r\n");
	ASSERT_EQ(r.status, 400);
	run_free(&r);
	run_init(&r, chunked, cfg());
	FEED(&r, "5 \r\nhello\r\n"); /* space after the size */
	ASSERT_EQ(r.status, 400);
	run_free(&r);
	run_init(&r, chunked, cfg());
	FEED(&r, "0x5\r\n");
	ASSERT_EQ(r.status, 400);
	run_free(&r);
}

TEST(chunk_ext)
{
	run r;
	run_init(&r, chunked, cfg());
	FEED(&r, "3;a=b;c=\"d e\"\r\nabc\r\n0;last\r\n\r\n");
	ASSERT_EQ(r.kind, BST_H1_BODY_DONE);
	ASSERT_EQ(r.datalen, 3);
	run_free(&r);
	run_init(&r, chunked, cfg());
	FEED(&r, "3;a\nb\r\nabc\r\n0\r\n\r\n"); /* bare LF inside */
	ASSERT_EQ(r.status, 400);
	run_free(&r);
	run_init(&r, chunked, cfg());
	FEED(&r, "3;a\rb\r\nabc\r\n0\r\n\r\n"); /* bare CR inside */
	ASSERT_EQ(r.status, 400);
	run_free(&r);
	run_init(&r, chunked, cfg());
	FEED(&r, "3;a\x01\r\nabc\r\n"); /* a control byte */
	ASSERT_EQ(r.status, 400);
	run_free(&r);
	/* the limit is on bytes after the ';' */
	bst_h1_body_cfg c = cfg();
	c.chunk_ext_limit = 4;
	run_init(&r, chunked, c);
	FEED(&r, "3;abcd\r\nabc\r\n0\r\n\r\n");
	ASSERT_EQ(r.kind, BST_H1_BODY_DONE);
	run_free(&r);
	run_init(&r, chunked, c);
	FEED(&r, "3;abcde\r\nabc\r\n0\r\n\r\n");
	ASSERT_EQ(r.status, 400);
	run_free(&r);
}

TEST(trailers)
{
	run r;
	run_init(&r, chunked, cfg());
	const char msg[] = "3\r\nabc\r\n0\r\nX-Sum: abc123\r\nContent-Length: 99\r\nHost: evil\r\n"
			   "Authorization: x\r\nTransfer-Encoding: gzip\r\nX-Other:  v \r\n\r\nNEXT";
	feed(&r, msg, sizeof msg - 1, 7);
	ASSERT_EQ(r.kind, BST_H1_BODY_DONE);
	ASSERT_EQ(r.used, sizeof msg - 1 - 4);
	ASSERT_EQ(r.trailers.n, 2); /* the forbidden ones are dropped */
	ASSERT(bst_str_eq(r.trailers.v[0].name, BST_S("X-Sum")));
	ASSERT(bst_str_eq(r.trailers.v[0].value, BST_S("abc123")));
	ASSERT(bst_str_eq(r.trailers.v[1].value, BST_S("v")));
	run_free(&r);
	/* bad trailer syntax */
	const char *bad[] = { "0\r\nX : v\r\n\r\n", "0\r\n x: v\r\n\r\n", "0\r\nX: a\nb\r\n\r\n",
			      "0\r\nnocolon\r\n\r\n", "0\r\n: v\r\n\r\n", "0\r\nX: a\rb\r\n\r\n" };
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		run_init(&r, chunked, cfg());
		feed(&r, bad[i], strlen(bad[i]), 0);
		if (r.status != 400)
			printf("# trailer case %zu: kind %d status %d\n", i, r.kind, r.status);
		ASSERT_EQ(r.kind, BST_H1_BODY_ERROR);
		ASSERT_EQ(r.status, 400);
		run_free(&r);
	}
	/* the size limit */
	bst_h1_body_cfg c = cfg();
	c.max_trailer = 16;
	run_init(&r, chunked, c);
	FEED(&r, "0\r\nX-Long: 0123456789\r\n\r\n");
	ASSERT_EQ(r.status, 431);
	run_free(&r);
	run_init(&r, chunked, c);
	FEED(&r, "0\r\nX: 012345678\r\n\r\n"); /* 16 bytes with its CRLF */
	ASSERT_EQ(r.kind, BST_H1_BODY_DONE);
	ASSERT_EQ(r.trailers.n, 1);
	run_free(&r);
	/* with no room at all, an empty trailer section is still fine */
	c.max_trailer = 0;
	run_init(&r, chunked, c);
	FEED(&r, "0\r\n\r\n");
	ASSERT_EQ(r.kind, BST_H1_BODY_DONE);
	run_free(&r);
}

TEST(missing_crlf_after_data)
{
	run r;
	run_init(&r, chunked, cfg());
	FEED(&r, "3\r\nabcde\r\n0\r\n\r\n"); /* data longer than its size */
	ASSERT_EQ(r.status, 400);
	run_free(&r);
	run_init(&r, chunked, cfg());
	FEED(&r, "3\r\nabc\n0\r\n\r\n"); /* LF alone after the data */
	ASSERT_EQ(r.status, 400);
	run_free(&r);
	run_init(&r, chunked, cfg());
	FEED(&r, "3\r\nabc\r0\r\n\r\n"); /* CR alone */
	ASSERT_EQ(r.status, 400);
	run_free(&r);
}

TEST(pipelined_after_body)
{
	run r;
	const char msg[] = "3\r\nabc\r\n0\r\n\r\nGET /next HTTP/1.1\r\n";
	run_init(&r, chunked, cfg());
	feed(&r, msg, sizeof msg - 1, 0);
	ASSERT_EQ(r.kind, BST_H1_BODY_DONE);
	ASSERT_EQ(r.used, 13);
	ASSERT(memcmp(msg + r.used, "GET /next", 9) == 0);
	run_free(&r);
}

TEST(max_body)
{
	bst_h1_body_cfg c = cfg();
	c.max_body = 10;
	run r;
	run_init(&r, chunked, c);
	FEED(&r, "5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n"); /* exactly 10 */
	ASSERT_EQ(r.kind, BST_H1_BODY_DONE);
	run_free(&r);
	run_init(&r, chunked, c);
	FEED(&r, "5\r\nhello\r\n6\r\n"); /* the second chunk would pass 10: no data read */
	ASSERT_EQ(r.status, 413);
	ASSERT_EQ(r.datalen, 5);
	run_free(&r);
	run_init(&r, (bst_framing){ .kind = BST_FRAMING_LENGTH, .length = 11 }, c);
	FEED(&r, "x");
	ASSERT_EQ(r.status, 413);
	run_free(&r);
	c.max_body = 0; /* unlimited */
	run_init(&r, chunked, c);
	FEED(&r, "FFFFFFFF\r\n");
	ASSERT_EQ(r.kind, BST_H1_BODY_MORE);
	run_free(&r);
}

TEST(error_is_sticky)
{
	run r;
	run_init(&r, chunked, cfg());
	FEED(&r, "zz\r\n");
	ASSERT_EQ(r.status, 400);
	bst_buf *b = bst_buf_new(5);
	memcpy(b->data, "0\r\n\r\n", 5);
	b->len = 5;
	size_t off = 0;
	int st = 0;
	ASSERT_EQ(bst_h1_body_feed(&r.b, b, &off, &r.out, NULL, &st), BST_H1_BODY_ERROR);
	ASSERT_EQ(st, 400);
	bst_buf_unref(b);
	run_free(&r);
}

TAP_MAIN()

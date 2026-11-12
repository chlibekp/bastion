/* The upstream response parser, its framing rules (RFC 9112 section 6.3), the response reader of
 * the proxy's HTTP/1.1 client and the request head it writes. */
#include "http/h1/resp_parser.h"
#include "proxy/client_h1.h"
#include "tap.h"

#include <string.h>

static bst_arena *A;

static int parse(const char *raw, bst_h1_resp_head *h)
{
	if (A != NULL)
		bst_arena_free(A);
	A = bst_arena_new(1 << 14);
	bst_h1_resp_parser p;
	bst_h1_resp_parser_init(&p, A);
	bst_h1_result r = bst_h1_parse_resp_head(&p, raw, strlen(raw), 8192, h);
	return r.kind == BST_H1_DONE ? 0 : r.kind == BST_H1_ERROR ? -1 : 1;
}

/* framing of raw for a GET (head=false) or HEAD request; -1 when refused or unparsable */
static int framing(const char *raw, bool head, bst_h1_resp_framing *f)
{
	bst_h1_resp_head h;
	if (parse(raw, &h) != 0)
		return -1;
	return bst_h1_resp_framing_of(&h, head, f);
}

TEST(resp_parse_basic)
{
	bst_h1_resp_head h;
	ASSERT_EQ(parse("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-A:  v  \r\n\r\n", &h), 0);
	ASSERT_EQ(h.status, 200);
	ASSERT_EQ(h.version_minor, 1);
	ASSERT(bst_str_eq(h.reason, BST_S("OK")));
	ASSERT_EQ(h.headers.n, 2);
	ASSERT(bst_str_eq(h.headers.v[1].value, BST_S("v")));
	ASSERT_EQ(parse("HTTP/1.0 404 \r\n\r\n", &h), 0); /* empty reason */
	ASSERT_EQ(parse("HTTP/1.1 204\r\n\r\n", &h), 0);     /* no reason at all */
	ASSERT_EQ(parse("HTTP/1.1 200 OK\r\nA: b\r\n", &h), 1);
	/* split anywhere: the same answer */
	const char *raw = "HTTP/1.1 301 Moved\r\nLocation: /x\r\n\r\n";
	bst_arena *a = bst_arena_new(4096);
	for (size_t cut = 1; cut < strlen(raw); cut++) {
		bst_h1_resp_parser p;
		bst_h1_resp_parser_init(&p, a);
		ASSERT_EQ(bst_h1_parse_resp_head(&p, raw, cut, 8192, &h).kind, BST_H1_NEED_MORE);
		bst_h1_result r = bst_h1_parse_resp_head(&p, raw, strlen(raw), 8192, &h);
		ASSERT_EQ(r.kind, BST_H1_DONE);
		ASSERT_EQ(r.consumed, strlen(raw));
		ASSERT_EQ(h.status, 301);
	}
	bst_arena_free(a);
}

TEST(resp_framing)
{
	static const struct {
		const char *raw;
		bool head;
		int rc;
		bst_resp_body kind;
		uint64_t len;
		bool keepalive;
	} t[] = {
		{ "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", false, 0, BST_RESP_BODY_LENGTH, 5, true },
		{ "HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\n", false, 0, BST_RESP_BODY_LENGTH, 5, true },
		{ "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", false, 0, BST_RESP_BODY_LENGTH, 5, true },
		{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", false, 0, BST_RESP_BODY_CHUNKED, 0, true },
		{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", false, 0, BST_RESP_BODY_CHUNKED, 0, true },
		{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", false, 0, BST_RESP_BODY_CLOSE, 0, false },
		{ "HTTP/1.1 200 OK\r\n\r\n", false, 0, BST_RESP_BODY_CLOSE, 0, false },
		{ "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 1\r\n\r\n", false, 0, BST_RESP_BODY_LENGTH, 1, false },
		{ "HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\n", false, 0, BST_RESP_BODY_LENGTH, 1, false },
		{ "HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n", false, 0, BST_RESP_BODY_NONE, 0, true },
		{ "HTTP/1.1 304 Not Modified\r\n\r\n", false, 0, BST_RESP_BODY_NONE, 0, true },
		{ "HTTP/1.1 103 Early Hints\r\n\r\n", false, 0, BST_RESP_BODY_NONE, 0, true },
		{ "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", true, 0, BST_RESP_BODY_NONE, 0, true },
		{ "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", false, -1, 0, 0, false },
		{ "HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n", false, -1, 0, 0, false },
		{ "HTTP/1.1 200 OK\r\nContent-Length: 5x\r\n\r\n", false, -1, 0, 0, false },
		{ "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n", false, -1, 0, 0, false },
		{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", false, -1, 0, 0, false },
		{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n", false, -1, 0, 0, false },
		{ "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", false, -1, 0, 0, false },
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
		bst_h1_resp_framing f;
		int rc = framing(t[i].raw, t[i].head, &f);
		if (rc != t[i].rc)
			printf("# case %zu: rc %d\n", i, rc);
		ASSERT_EQ(rc, t[i].rc);
		if (rc != 0)
			continue;
		if (f.kind != t[i].kind || f.length != t[i].len || f.keepalive != t[i].keepalive)
			printf("# case %zu: kind %d len %llu ka %d\n", i, f.kind,
			       (unsigned long long)f.length, f.keepalive);
		ASSERT_EQ(f.kind, t[i].kind);
		ASSERT_EQ(f.length, t[i].len);
		ASSERT_EQ(f.keepalive, t[i].keepalive);
	}
}

TEST(resp_cl_te_both)
{
	bst_h1_resp_framing f;
	ASSERT_EQ(framing("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
			  false, &f), -1);
	ASSERT_EQ(framing("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
			  true, &f), -1); /* even where no body follows */
}

TEST(resp_splitting)
{
	bst_h1_resp_head h;
	ASSERT_EQ(parse("HTTP/1.1 200 OK\r\nX: a\rInjected: 1\r\n\r\n", &h), -1);
	ASSERT_EQ(parse("HTTP/1.1 200 OK\r\nX: a\nInjected: 1\r\n\r\n", &h), -1);
	ASSERT_EQ(parse("HTTP/1.1 200 OK\nX: a\r\n\r\n", &h), -1);
	ASSERT_EQ(parse("HTTP/1.1 200 O\x01K\r\n\r\n", &h), -1);
	ASSERT_EQ(parse("HTTP/1.1 200 OK\r\nX: a\x0b" "b\r\n\r\n", &h), -1); /* VT */
	ASSERT_EQ(parse("HTTP/1.1 200 OK\r\nX : a\r\n\r\n", &h), -1);
	ASSERT_EQ(parse("HTTP/1.1 200 OK\r\nX: a\r\n folded\r\n\r\n", &h), -1);
	ASSERT_EQ(parse("HTTP/1.1 200 OK\r\n: a\r\n\r\n", &h), -1);
	ASSERT_EQ(parse("HTTP/2 200 OK\r\n\r\n", &h), -1);
	ASSERT_EQ(parse("HTTP/1.1 99 OK\r\n\r\n", &h), -1);
	ASSERT_EQ(parse("HTTP/1.1 2000 OK\r\n\r\n", &h), -1);
	ASSERT_EQ(parse("http/1.1 200 OK\r\n\r\n", &h), -1);
	/* a value with a NUL in the middle, given by length */
	bst_arena *a = bst_arena_new(4096);
	bst_h1_resp_parser p;
	bst_h1_resp_parser_init(&p, a);
	static const char nul[] = "HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\n";
	ASSERT_EQ(bst_h1_parse_resp_head(&p, nul, sizeof nul - 1, 8192, &h).kind, BST_H1_ERROR);
	/* longer than the limit */
	bst_h1_resp_parser_init(&p, a);
	char big[200];
	memset(big, 'a', sizeof big);
	memcpy(big, "HTTP/1.1 200 OK\r\nX: ", 20);
	ASSERT_EQ(bst_h1_parse_resp_head(&p, big, sizeof big, 100, &h).kind, BST_H1_ERROR);
	bst_arena_free(a);
}

static bst_buf *buf_of(const char *s)
{
	size_t n = strlen(s);
	bst_buf *b = bst_buf_new(n);
	memcpy(b->data, s, n);
	b->len = n;
	return b;
}

/* Runs the reader over raw, all in one read: the last event and the bytes left over. */
static bst_upc_ev read_all(bst_h1_client *c, const char *raw, size_t *left, uint64_t *body)
{
	bst_slab *slab = bst_chain_slab_new(64);
	bst_chain out;
	bst_chain_init(&out, slab);
	bst_buf *b = buf_of(raw);
	size_t off = 0;
	bst_upc_ev ev;
	do
		ev = bst_h1_client_feed(c, b, &off, &out);
	while (ev == BST_UPC_HEAD || ev == BST_UPC_INTERIM || ev == BST_UPC_BODY);
	*left = b->len - off;
	*body = bst_chain_len(&out);
	bst_chain_clear(&out);
	bst_slab_free(slab);
	bst_buf_unref(b);
	return ev;
}

TEST(resp_excess_after_body)
{
	bst_arena *a = bst_arena_new(4096);
	bst_h1_body_cfg bc = { .chunk_ext_limit = 1024, .max_trailer = 1024 };
	bst_h1_client c;
	size_t left;
	uint64_t body;
	bst_h1_client_init(&c, a, 8192, false, &bc);
	ASSERT_EQ(read_all(&c, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", &left, &body),
		  BST_UPC_DONE);
	ASSERT_EQ(left, 0);
	ASSERT_EQ(body, 3);
	ASSERT(bst_h1_client_reusable(&c));
	bst_h1_client_free(&c);

	bst_h1_client_init(&c, a, 8192, false, &bc);
	ASSERT_EQ(read_all(&c, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 200", &left,
			   &body), BST_UPC_DONE);
	ASSERT_EQ(left, 12); /* the caller sees bytes past the end: not reusable */
	bst_h1_client_free(&c);

	/* chunked, with a 100 and a 103 first */
	bst_h1_client_init(&c, a, 8192, false, &bc);
	ASSERT_EQ(read_all(&c, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
			       "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n0\r\n\r\n",
			   &left, &body), BST_UPC_DONE);
	ASSERT_EQ(body, 4);
	ASSERT_EQ(left, 0);
	bst_h1_client_free(&c);

	/* close-delimited: only EOF ends it, and it is never reusable */
	bst_h1_client_init(&c, a, 8192, false, &bc);
	ASSERT_EQ(read_all(&c, "HTTP/1.1 200 OK\r\n\r\nall of it", &left, &body), BST_UPC_MORE);
	ASSERT_EQ(body, 9);
	ASSERT_EQ(bst_h1_client_eof(&c), BST_UPC_DONE);
	ASSERT(!bst_h1_client_reusable(&c));
	bst_h1_client_free(&c);

	/* a Content-Length body cut short by EOF is an error, never a clean end */
	bst_h1_client_init(&c, a, 8192, false, &bc);
	ASSERT_EQ(read_all(&c, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", &left, &body),
		  BST_UPC_MORE);
	ASSERT_EQ(bst_h1_client_eof(&c), BST_UPC_ERROR);
	bst_h1_client_free(&c);
	bst_arena_free(a);
}

TEST(req_head_regenerated)
{
	bst_arena *a = bst_arena_new(4096);
	bst_headers hs;
	bst_headers_init(&hs, a);
	bst_headers_add(&hs, BST_S("Accept"), BST_S("*/*"));
	bst_h1_req_out r = { .method = BST_S("POST"), .target = BST_S("/a%20b?x=1"),
			     .host = BST_S("up.test"), .headers = &hs, .has_length = true,
			     .length = 7 };
	bst_buf *b = bst_h1_req_head(&r);
	ASSERT(b != NULL);
	const char *want = "POST /a%20b?x=1 HTTP/1.1\r\nHost: up.test\r\nAccept: */*\r\n"
			   "Content-Length: 7\r\n\r\n";
	ASSERT_EQ(b->len, strlen(want));
	ASSERT(memcmp(b->data, want, b->len) == 0);
	bst_buf_unref(b);
	r.has_length = false;
	r.chunked = true;
	b = bst_h1_req_head(&r);
	ASSERT(b != NULL && memmem(b->data, b->len, "Transfer-Encoding: chunked\r\n\r\n", 30) != NULL);
	bst_buf_unref(b);
	/* nothing that could split the request is written */
	r.target = BST_S("/a b");
	ASSERT(bst_h1_req_head(&r) == NULL);
	r.target = BST_S("/a");
	bst_headers_add(&hs, BST_S("X"), BST_S("a\r\nInjected: 1"));
	ASSERT(bst_h1_req_head(&r) == NULL);
	bst_arena_free(a);
}

TAP_MAIN()

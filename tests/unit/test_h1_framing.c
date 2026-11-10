#include "corpus.h"
#include "http/h1/parser.h"
#include "http/semantics.h"
#include "tap.h"

/* Head, framing, then request semantics: the first refusal's status, 0 when all pass. */
static int pipeline(const char *raw, size_t n, bst_req *req, bst_arena *a)
{
	bst_h1_limits lim = { .max_uri = 8192, .max_head = 16384, .max_headers = 100 };
	bst_h1_parser p;
	bst_h1_parser_init(&p, a);
	bst_h1_result r = bst_h1_parse_head(&p, raw, n, &lim, &req->head);
	if (r.kind == BST_H1_ERROR)
		return r.status;
	if (r.kind != BST_H1_DONE)
		return -1;
	int st = 0;
	req->framing = bst_h1_message_framing(&req->head, &st);
	if (st != 0)
		return st;
	return bst_validate_request_semantics(req);
}

#define RUN(lit, req, a) pipeline((lit), sizeof(lit) - 1, (req), (a))

static const struct {
	const char *name;
	const char *raw;
	int status;
} table[] = {
	{ "cl_te_both", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n", 400 },
	{ "cl_list_same", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\n", 400 },
	{ "cl_dup_same", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", 400 },
	{ "cl_dup_diff", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", 400 },
	{ "cl_plus", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\n", 400 },
	{ "cl_hex", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0x5\r\n\r\n", 400 },
	{ "cl_overflow", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n", 400 },
	{ "cl_space_before_colon", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length : 5\r\n\r\n", 400 },
	{ "te_identity", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity\r\n\r\n", 400 },
	{ "te_xchunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n", 400 },
	{ "te_chunked_gzip", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", 400 },
	{ "te_gzip_chunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 501 },
	{ "te_chunked_chunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, chunked\r\n\r\n", 400 },
	{ "te_http10", "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n", 400 },
	{ "obs_fold", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n x\r\n\r\n", 400 },
	{ "host_missing", "GET / HTTP/1.1\r\n\r\n", 400 },
	{ "host_dup", "GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n", 400 },
	{ "host_invalid", "GET / HTTP/1.1\r\nHost: a/b\r\n\r\n", 400 },
	{ "host_invalid_port", "GET / HTTP/1.1\r\nHost: a:1234567\r\n\r\n", 400 },
	{ "host_http10_ok", "GET / HTTP/1.0\r\n\r\n", 0 },
	{ "host_ipv6_ok", "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n", 0 },
	{ "te_chunked_ok", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", 0 },
	{ "te_chunked_case_ok", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:  CHUNKED \r\n\r\n", 0 },
	{ "cl_ok", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n", 0 },
};

TEST(framing_table)
{
	for (size_t i = 0; i < sizeof table / sizeof table[0]; i++) {
		bst_arena *a = bst_arena_new(4096);
		bst_req req;
		int st = pipeline(table[i].raw, strlen(table[i].raw), &req, a);
		if (st != table[i].status)
			printf("# %s: got %d, want %d\n", table[i].name, st, table[i].status);
		ASSERT_EQ(st, table[i].status);
		bst_arena_free(a);
	}
}

TEST(framing_values)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req r;
	ASSERT_EQ(RUN("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n", &r, a), 0);
	ASSERT_EQ(r.framing.kind, BST_FRAMING_LENGTH);
	ASSERT_EQ(r.framing.length, 12);
	ASSERT_EQ(RUN("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n", &r, a), 0);
	ASSERT_EQ(r.framing.kind, BST_FRAMING_NONE);
	ASSERT_EQ(RUN("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551615\r\n\r\n", &r, a), 0);
	ASSERT_EQ(r.framing.length, UINT64_MAX);
	ASSERT_EQ(RUN("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", &r, a), 0);
	ASSERT_EQ(r.framing.kind, BST_FRAMING_CHUNKED);
	ASSERT_EQ(RUN("GET / HTTP/1.1\r\nHost: a\r\n\r\n", &r, a), 0);
	ASSERT_EQ(r.framing.kind, BST_FRAMING_NONE);
	bst_arena_free(a);
}

TEST(host_uses_target_when_absolute)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req r;
	ASSERT_EQ(RUN("GET http://real.example:81/x HTTP/1.1\r\nHost: other.example\r\n\r\n", &r, a), 0);
	ASSERT(bst_str_eq(r.host, BST_S("real.example:81")));
	ASSERT_EQ(RUN("GET /x HTTP/1.1\r\nHost: plain.example\r\n\r\n", &r, a), 0);
	ASSERT(bst_str_eq(r.host, BST_S("plain.example")));
	ASSERT_EQ(RUN("GET / HTTP/1.0\r\n\r\n", &r, a), 0);
	ASSERT_EQ(r.host.len, 0);
	bst_arena_free(a);
}

TEST(connection_tokens)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req r;
	ASSERT_EQ(RUN("GET / HTTP/1.1\r\nHost: a\r\n\r\n", &r, a), 0);
	ASSERT(r.keepalive);
	ASSERT_EQ(RUN("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", &r, a), 0);
	ASSERT(!r.keepalive);
	ASSERT_EQ(RUN("GET / HTTP/1.1\r\nHost: a\r\nConnection: TE, Close\r\n\r\n", &r, a), 0);
	ASSERT(!r.keepalive);
	ASSERT_EQ(RUN("GET / HTTP/1.1\r\nHost: a\r\nConnection: x\r\nConnection: close\r\n\r\n", &r, a), 0);
	ASSERT(!r.keepalive); /* tokens of every line count */
	ASSERT_EQ(RUN("GET / HTTP/1.0\r\n\r\n", &r, a), 0);
	ASSERT(!r.keepalive);
	ASSERT_EQ(RUN("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", &r, a), 0);
	ASSERT(r.keepalive);
	ASSERT_EQ(RUN("GET / HTTP/1.0\r\nConnection: keep-alive, close\r\n\r\n", &r, a), 0);
	ASSERT(!r.keepalive); /* close wins */
	ASSERT_EQ(RUN("GET / HTTP/1.1\r\nHost: a\r\nConnection: ,, keep-alive ,\r\n\r\n", &r, a), 0);
	ASSERT(r.keepalive); /* empty list elements are legal */
	bst_arena_free(a);
}

TEST(expect_and_methods)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req r;
	ASSERT_EQ(RUN("POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-Continue\r\nContent-Length: 1\r\n\r\n", &r, a), 0);
	ASSERT(r.expect_continue);
	ASSERT_EQ(RUN("POST / HTTP/1.1\r\nHost: a\r\nExpect: nope\r\n\r\n", &r, a), 417);
	ASSERT_EQ(RUN("POST / HTTP/1.0\r\nExpect: nope\r\n\r\n", &r, a), 0); /* 1.0 has no expectations */
	ASSERT(!r.expect_continue);
	ASSERT_EQ(RUN("TRACE / HTTP/1.1\r\nHost: a\r\n\r\n", &r, a), 405);
	ASSERT_EQ(RUN("CONNECT h:1 HTTP/1.1\r\nHost: h:1\r\n\r\n", &r, a), 405);
	ASSERT_EQ(RUN("PURGE / HTTP/1.1\r\nHost: a\r\n\r\n", &r, a), 501);
	ASSERT_EQ(RUN("OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n", &r, a), 0);
	bst_arena_free(a);
}

/* Every desync input stored in tests/corpus/smuggling is refused with its status, and every
 * valid neighbour is accepted. */
TEST(smuggling_corpus)
{
	corpus_entry *c;
	size_t n = corpus_load("tests/corpus/smuggling", &c);
	ASSERT(n >= 40);
	size_t refused = 0;
	for (size_t i = 0; i < n; i++) {
		bst_arena *a = bst_arena_new(4096);
		bst_req r;
		int st = pipeline(c[i].data, c[i].len, &r, a);
		if (st != c[i].expect)
			printf("# %s: got %d, want %d\n", c[i].name, st, c[i].expect);
		ASSERT_EQ(st, c[i].expect);
		refused += c[i].expect != 0;
		bst_arena_free(a);
		free(c[i].data);
	}
	ASSERT(refused >= 35);
	free(c);
}

TAP_MAIN()

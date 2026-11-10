#include "corpus.h"
#include "http/h1/parser.h"
#include "http/h1/scan.h"
#include "tap.h"

static bst_h1_limits defaults(void)
{
	return (bst_h1_limits){ .max_uri = 8192, .max_head = 16384, .max_headers = 100 };
}

static bst_h1_result parse(const char *s, size_t n, const bst_h1_limits *lim, bst_req_head *h,
			   bst_arena *a)
{
	bst_h1_parser p;
	bst_h1_parser_init(&p, a);
	return bst_h1_parse_head(&p, s, n, lim, h);
}

#define PARSE(lit, lim, h, a) parse((lit), sizeof(lit) - 1, (lim), (h), (a))

static bool same_head(const bst_req_head *a, const bst_req_head *b)
{
	if (a->method != b->method || a->form != b->form || a->has_query != b->has_query ||
	    a->version_minor != b->version_minor || a->headers.n != b->headers.n)
		return false;
	if (!bst_str_eq(a->method_str, b->method_str) || !bst_str_eq(a->target, b->target) ||
	    !bst_str_eq(a->scheme, b->scheme) || !bst_str_eq(a->authority, b->authority) ||
	    !bst_str_eq(a->path, b->path) || !bst_str_eq(a->query, b->query))
		return false;
	for (uint32_t i = 0; i < a->headers.n; i++)
		if (!bst_str_eq(a->headers.v[i].name, b->headers.v[i].name) ||
		    !bst_str_eq(a->headers.v[i].value, b->headers.v[i].value) ||
		    a->headers.v[i].id != b->headers.v[i].id)
			return false;
	return true;
}

static bool same_result(bst_h1_result a, bst_h1_result b)
{
	return a.kind == b.kind && a.status == b.status && a.consumed == b.consumed;
}

#define CORPUS "tests/corpus/h1"

TEST(all_splits)
{
	corpus_entry *c;
	size_t n = corpus_load(CORPUS, &c);
	ASSERT(n >= 30);
	bst_h1_limits lim = defaults();
	for (size_t k = 0; k < n; k++) {
		bst_arena *wa = bst_arena_new(4096);
		bst_req_head whole;
		bst_h1_result w = parse(c[k].data, c[k].len, &lim, &whole, wa);
		ASSERT(w.kind != BST_H1_NEED_MORE);
		ASSERT_EQ(w.kind == BST_H1_DONE, c[k].expect == 0);
		if (c[k].expect != 0)
			ASSERT_EQ(w.status, c[k].expect);
		if (c[k].expect == 0)
			ASSERT(w.consumed > 0 && w.consumed <= c[k].len);
		/* a head that took part of the buffer: the rest is the body or the next request */
		for (size_t cut = 0; cut <= c[k].len; cut++) {
			bst_arena *a = bst_arena_new(4096);
			bst_h1_parser p;
			bst_req_head h;
			bst_h1_parser_init(&p, a);
			bst_h1_result r = bst_h1_parse_head(&p, c[k].data, cut, &lim, &h);
			if (r.kind == BST_H1_NEED_MORE)
				r = bst_h1_parse_head(&p, c[k].data, c[k].len, &lim, &h);
			if (!same_result(r, w) || (w.kind == BST_H1_DONE && !same_head(&h, &whole))) {
				printf("# %s split at %zu differs\n", c[k].name, cut);
				ASSERT(0);
			}
			bst_arena_free(a);
		}
		/* one byte at a time, the buffer reallocated each time so no pointer can be kept */
		bst_arena *a = bst_arena_new(4096);
		bst_h1_parser p;
		bst_req_head h;
		bst_h1_parser_init(&p, a);
		bst_h1_result r = { .kind = BST_H1_NEED_MORE };
		for (size_t len = 1; len <= c[k].len && r.kind == BST_H1_NEED_MORE; len++) {
			char *copy = malloc(len);
			memcpy(copy, c[k].data, len);
			r = bst_h1_parse_head(&p, copy, len, &lim, &h);
			free(copy);
		}
		if (!same_result(r, w) || (w.kind == BST_H1_DONE && !same_head(&h, &whole))) {
			printf("# %s byte-by-byte differs\n", c[k].name);
			ASSERT(0);
		}
		bst_arena_free(a);
		bst_arena_free(wa);
		free(c[k].data);
	}
	free(c);
}

TEST(simple_get_fields)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req_head h;
	bst_h1_limits lim = defaults();
	bst_h1_result r = PARSE("GET /a/b?x=1 HTTP/1.1\r\nHost: h\r\nX-A:  padded \t\r\n\r\nBODY", &lim, &h, a);
	ASSERT_EQ(r.kind, BST_H1_DONE);
	ASSERT_EQ(r.consumed, strlen("GET /a/b?x=1 HTTP/1.1\r\nHost: h\r\nX-A:  padded \t\r\n\r\n"));
	ASSERT_EQ(h.method, BST_M_GET);
	ASSERT(bst_str_eq(h.path, BST_S("/a/b")) && bst_str_eq(h.query, BST_S("x=1")) && h.has_query);
	ASSERT_EQ(h.version_minor, 1);
	ASSERT_EQ(h.headers.n, 2);
	ASSERT(bst_str_eq(h.headers.v[1].value, BST_S("padded"))); /* OWS trimmed both sides */
	ASSERT_EQ(h.headers.v[0].id, BST_H_HOST);
	bst_arena_free(a);
}

TEST(target_forms)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req_head h;
	bst_h1_limits lim = defaults();
	ASSERT_EQ(PARSE("GET /p HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT_EQ(h.form, BST_TARGET_ORIGIN);
	ASSERT(!h.has_query && bst_str_eq(h.path, BST_S("/p")));
	ASSERT_EQ(PARSE("GET /p? HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT(h.has_query && h.query.len == 0);
	ASSERT_EQ(PARSE("GET http://h.example:81/x?y HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT_EQ(h.form, BST_TARGET_ABSOLUTE);
	ASSERT(bst_str_eq(h.scheme, BST_S("http")) && bst_str_eq(h.authority, BST_S("h.example:81")));
	ASSERT(bst_str_eq(h.path, BST_S("/x")) && bst_str_eq(h.query, BST_S("y")));
	ASSERT_EQ(PARSE("GET http://h.example HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT(bst_str_eq(h.path, BST_S("/")));
	ASSERT_EQ(PARSE("CONNECT h.example:443 HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT_EQ(h.form, BST_TARGET_AUTHORITY);
	ASSERT(bst_str_eq(h.authority, BST_S("h.example:443")));
	ASSERT_EQ(PARSE("OPTIONS * HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT_EQ(h.form, BST_TARGET_ASTERISK);
	/* a form is valid only with its own method */
	ASSERT_EQ(PARSE("GET * HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("POST h:1 HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("CONNECT /x HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("CONNECT http://h:1/ HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET http://u@h/ HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400); /* userinfo */
	ASSERT_EQ(PARSE("GET http:///x HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET x HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	bst_arena_free(a);
}

TEST(method_token)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req_head h;
	bst_h1_limits lim = defaults();
	ASSERT_EQ(PARSE("PURGE / HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT_EQ(h.method, BST_M_UNKNOWN);
	ASSERT(bst_str_eq(h.method_str, BST_S("PURGE")));
	ASSERT_EQ(PARSE("get / HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE); /* case is data */
	ASSERT_EQ(h.method, BST_M_UNKNOWN);
	ASSERT_EQ(PARSE("G(T / HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("G\"T / HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE(" GET / HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("\tGET / HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	bst_arena_free(a);
}

TEST(version)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req_head h;
	bst_h1_limits lim = defaults();
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT_EQ(h.version_minor, 1);
	ASSERT_EQ(PARSE("GET / HTTP/1.0\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT_EQ(h.version_minor, 0);
	ASSERT_EQ(PARSE("GET / HTTP/1.7\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT_EQ(h.version_minor, 1); /* RFC 9112 section 2.3: a higher minor is read as 1.1 */
	ASSERT_EQ(PARSE("GET / HTTP/2.0\r\n\r\n", &lim, &h, a).status, 505);
	ASSERT_EQ(PARSE("GET / HTTP/3.0\r\n\r\n", &lim, &h, a).status, 505);
	ASSERT_EQ(PARSE("GET / http/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET / HTTP/1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET / HTTP/1.10\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET / HTTP/1.1 \r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET / HTTP/1.1x\r\n\r\n", &lim, &h, a).status, 400);
	bst_arena_free(a);
}

TEST(leading_crlf)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req_head h;
	bst_h1_limits lim = defaults();
	ASSERT_EQ(PARSE("\r\nGET / HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT_EQ(PARSE("\r\n\r\nGET / HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("\nGET / HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	lim.allow_bare_lf = true;
	ASSERT_EQ(PARSE("\nGET / HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	bst_arena_free(a);
}

TEST(limits)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req_head h;
	bst_h1_limits lim = { .max_uri = 20, .max_head = 200, .max_headers = 3 };
	/* a 20-byte target is the largest that fits; 21 is 414, found as the byte arrives */
	ASSERT_EQ(PARSE("GET /aaaaaaaaaaaaaaaaaaa HTTP/1.1\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT_EQ(PARSE("GET /aaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\n\r\n", &lim, &h, a).status, 414);
	ASSERT_EQ(PARSE("GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &lim, &h, a).status, 414);
	/* too many headers: 3 pass, the fourth is 431 */
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n\r\n", &lim, &h, a).status, 431);
	/* too many bytes: refused before the head ends, from the first byte over, not at the end */
	lim = (bst_h1_limits){ .max_uri = 100, .max_head = 40, .max_headers = 100 };
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nX: 0123456789012345678901234\r\n\r\n", &lim, &h, a).status, 431);
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nX: 012345678901234567890", &lim, &h, a).kind, BST_H1_NEED_MORE);
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nX: 0123456789012345678901", &lim, &h, a).status, 431);
	/* a head of exactly max_head bytes is fine */
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nX: 01234567890123456\r\n\r\n", &lim, &h, a).kind, BST_H1_DONE);
	bst_arena_free(a);
}

TEST(control_chars)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req_head h;
	bst_h1_limits lim = defaults();
	ASSERT_EQ(PARSE("GET /a\x01 HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET /a\x7f HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET /a\tb HTTP/1.1\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(parse("GET /a\0b HTTP/1.1\r\n\r\n", 21, &lim, &h, a).status, 400);
	ASSERT_EQ(parse("GET / HTTP/1.1\r\nX: a\0b\r\n\r\n", 26, &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nX: a\x0b\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nX: a\x7f\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nX: a\rb\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nX: a\r\r\n\r\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET / HTTP/1.1\rX: a\r\n\r\n", &lim, &h, a).status, 400);
	/* bare LF: refused unless http1_allow_bare_lf, then every line may end in LF alone */
	ASSERT_EQ(PARSE("GET / HTTP/1.1\nHost: h\n\n", &lim, &h, a).status, 400);
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nHost: h\n\r\n", &lim, &h, a).status, 400);
	lim.allow_bare_lf = true;
	bst_h1_result r = PARSE("GET / HTTP/1.1\nHost: h\n\n", &lim, &h, a);
	ASSERT_EQ(r.kind, BST_H1_DONE);
	ASSERT_EQ(h.headers.n, 1);
	ASSERT(bst_str_eq(h.headers.v[0].value, BST_S("h")));
	ASSERT_EQ(PARSE("GET / HTTP/1.1\r\nX: a\rb\n\n", &lim, &h, a).status, 400); /* CR stays bad */
	bst_arena_free(a);
}

TEST(error_is_sticky_and_need_more)
{
	bst_arena *a = bst_arena_new(4096);
	bst_h1_parser p;
	bst_req_head h;
	bst_h1_limits lim = defaults();
	bst_h1_parser_init(&p, a);
	const char bad[] = "GET / http/1.1\r\n\r\n";
	ASSERT_EQ(bst_h1_parse_head(&p, bad, 14, &lim, &h).status, 400);
	ASSERT_EQ(bst_h1_parse_head(&p, bad, sizeof bad - 1, &lim, &h).status, 400);
	bst_h1_parser_init(&p, a);
	ASSERT_EQ(bst_h1_parse_head(&p, "GET / HT", 8, &lim, &h).kind, BST_H1_NEED_MORE);
	ASSERT_EQ(bst_h1_parse_head(&p, "", 0, &lim, &h).status, 500); /* a shrinking buffer */
	bst_arena_free(a);
}

TEST(head_is_copied_out_of_the_buffer)
{
	bst_arena *a = bst_arena_new(4096);
	bst_req_head h;
	bst_h1_limits lim = defaults();
	char buf[] = "GET /abc HTTP/1.1\r\nHost: h\r\n\r\n";
	ASSERT_EQ(parse(buf, sizeof buf - 1, &lim, &h, a).kind, BST_H1_DONE);
	memset(buf, 'Z', sizeof buf - 1); /* the caller reuses its buffer */
	ASSERT(bst_str_eq(h.path, BST_S("/abc")));
	ASSERT(bst_str_eq(h.headers.v[0].value, BST_S("h")));
	bst_arena_free(a);
}

/* Every vector path gives the scalar answer, on edges and on random data. */
TEST(scan_kinds_agree)
{
	unsigned avail = bst_h1_scan_available();
	ASSERT(avail & BST_SCAN_SCALAR);
	srand(12345);
	for (unsigned kind = 2; kind <= 8; kind <<= 1) {
		if (!(avail & kind))
			continue;
		for (int round = 0; round < 3000; round++) {
			unsigned char buf[200];
			size_t n = (size_t)(rand() % 130);
			size_t off = (size_t)(rand() % 40);
			for (size_t i = 0; i < n + off; i++)
				buf[i] = (unsigned char)(0x21 + rand() % 0x5e);
			if (round % 3 != 0 && n > 0) /* one bad byte somewhere */
				buf[off + (size_t)rand() % n] = (unsigned char)(rand() % 256);
			if (round % 7 == 0 && n > 0)
				buf[off + (size_t)rand() % n] = (unsigned char)(rand() % 3 ? 0x7f : 0x09);
			ASSERT(bst_h1_scan_select(BST_SCAN_SCALAR));
			size_t v0 = bst_h1_scan_value((const char *)buf + off, n);
			size_t t0 = bst_h1_scan_target((const char *)buf + off, n);
			ASSERT(bst_h1_scan_select((bst_h1_scan_kind)kind));
			size_t v1 = bst_h1_scan_value((const char *)buf + off, n);
			size_t t1 = bst_h1_scan_target((const char *)buf + off, n);
			if (v0 != v1 || t0 != t1) {
				printf("# kind %s differs: value %zu/%zu target %zu/%zu\n",
				       bst_h1_scan_name(), v1, v0, t1, t0);
				ASSERT(0);
			}
		}
	}
	/* the byte classes themselves */
	ASSERT(bst_h1_scan_select(BST_SCAN_SCALAR));
	for (int c = 0; c < 256; c++) {
		char one = (char)c;
		ASSERT_EQ(bst_h1_scan_value(&one, 1), (c == 9 || (c >= 0x20 && c != 0x7f)) ? 1 : 0);
		ASSERT_EQ(bst_h1_scan_target(&one, 1), (c > 0x20 && c < 0x7f) ? 1 : 0);
	}
	ASSERT(bst_h1_scan_select(0));
	printf("# scan paths available: mask %u, in use %s\n", avail, bst_h1_scan_name());
}

TAP_MAIN()

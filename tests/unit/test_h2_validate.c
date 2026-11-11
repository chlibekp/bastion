/* Validation of an HTTP/2 request's fields (src/http/validate_pseudo.c, RFC 9113 section 8): what
 * becomes a bst_req_head and what is refused before any handler sees it. */
#include "http/validate_pseudo.h"
#include "tap.h"

#include <stdarg.h>
#include <string.h>

static bst_arena *A;

/* A field list from name, value pairs ending with NULL. */
static void fields(bst_headers *h, ...)
{
	bst_headers_init(h, A);
	va_list ap;
	va_start(ap, h);
	const char *n;
	while ((n = va_arg(ap, const char *)) != NULL) {
		const char *v = va_arg(ap, const char *);
		bst_headers_add(h, (bst_str){ n, (uint32_t)strlen(n) }, (bst_str){ v, (uint32_t)strlen(v) });
	}
	va_end(ap);
}

static bst_pseudo_rc check(const bst_headers *in, bool end, bst_req_head *out, bst_pseudo_result *res)
{
	memset(out, 0, sizeof *out);
	bst_headers_init(&out->headers, A);
	bst_pseudo_opts o = { .end_stream = end };
	return bst_validate_pseudo_request(in, A, out, &o, res);
}

#define BASE ":method", "GET", ":scheme", "https", ":authority", "example.test", ":path", "/x?y=1"

TEST(pseudo_rules)
{
	A = bst_arena_new(1 << 14);
	bst_headers h;
	bst_req_head r;
	bst_pseudo_result res;
	fields(&h, BASE, NULL);
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_OK);
	ASSERT(bst_str_eq(r.path, BST_S("/x")) && r.has_query && bst_str_eq(r.query, BST_S("y=1")));
	ASSERT(bst_str_eq(r.authority, BST_S("example.test")));
	ASSERT(bst_headers_get_name(&r.headers, BST_S("host")) != NULL); /* an HTTP/1.1 view of the request */

	fields(&h, ":method", "GET", ":scheme", "https", ":path", "/", NULL); /* no :authority and no Host */
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_BAD_REQUEST);
	fields(&h, ":method", "GET", ":authority", "a", ":path", "/", NULL); /* no :scheme */
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED);
	fields(&h, ":method", "GET", ":scheme", "https", ":authority", "a", NULL); /* no :path */
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED);
	fields(&h, BASE, ":path", "/again", NULL); /* a pseudo-header twice */
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED);
	fields(&h, ":method", "GET", ":scheme", "https", ":authority", "a", "accept", "*/*", ":path", "/", NULL);
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED); /* a pseudo-header after a regular field */
	fields(&h, BASE, ":status", "200", NULL); /* a response pseudo-header in a request */
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED);
	fields(&h, ":method", "GET", ":scheme", "https", ":authority", "a", ":path", "x", NULL);
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED); /* not an origin-form target */
	fields(&h, ":method", "CONNECT", ":authority", "a:443", NULL); /* CONNECT has only :authority */
	ASSERT_EQ(check(&h, false, &r, &res), BST_PSEUDO_OK);
	fields(&h, ":method", "CONNECT", ":authority", "a:443", ":path", "/", ":scheme", "https", NULL);
	ASSERT_EQ(check(&h, false, &r, &res), BST_PSEUDO_MALFORMED);
	fields(&h, BASE, ":protocol", "websocket", NULL); /* :protocol is refused unless it was advertised */
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED);
	bst_arena_free(A);
}

TEST(name_rules)
{
	ASSERT(bst_pseudo_name_ok(BST_S("accept-encoding")));
	ASSERT(bst_pseudo_name_ok(BST_S(":path")));
	ASSERT(!bst_pseudo_name_ok(BST_S("Accept"))); /* upper case is malformed in HTTP/2 */
	ASSERT(!bst_pseudo_name_ok(BST_S("")));
	ASSERT(!bst_pseudo_name_ok(BST_S("a b")));
	ASSERT(!bst_pseudo_name_ok(BST_S("a:b")));
	ASSERT(!bst_pseudo_name_ok(BST_S("a\r\nb")));
	A = bst_arena_new(1 << 14);
	bst_headers h;
	bst_req_head r;
	bst_pseudo_result res;
	fields(&h, BASE, "X-Upper", "1", NULL);
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED);
	bst_arena_free(A);
}

TEST(value_rules)
{
	ASSERT(bst_pseudo_value_ok(BST_S("text/html; charset=utf-8")));
	ASSERT(bst_pseudo_value_ok(BST_S("")));
	ASSERT(!bst_pseudo_value_ok(BST_S("a\nb")));
	ASSERT(!bst_pseudo_value_ok(BST_S("a\rb")));
	ASSERT(!bst_pseudo_value_ok((bst_str){ "a\0b", 3 }));
	ASSERT(!bst_pseudo_value_ok(BST_S(" lead")));
	ASSERT(!bst_pseudo_value_ok(BST_S("trail ")));
	A = bst_arena_new(1 << 14);
	bst_headers h;
	bst_req_head r;
	bst_pseudo_result res;
	fields(&h, BASE, "x-a", "b\r\nx-injected: 1", NULL); /* a header-injection attempt */
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED);
	bst_arena_free(A);
}

TEST(connection_headers)
{
	A = bst_arena_new(1 << 14);
	static const char *const bad[] = { "connection", "keep-alive", "proxy-connection", "transfer-encoding",
					   "upgrade" };
	bst_headers h;
	bst_req_head r;
	bst_pseudo_result res;
	for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
		fields(&h, BASE, bad[i], "x", NULL);
		ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED); /* RFC 9113 section 8.2.2 */
	}
	fields(&h, BASE, "te", "trailers", NULL); /* the one TE value that is allowed */
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_OK);
	fields(&h, BASE, "te", "gzip", NULL);
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED);
	bst_arena_free(A);
}

TEST(content_length_mismatch)
{
	A = bst_arena_new(1 << 14);
	bst_headers h;
	bst_req_head r;
	bst_pseudo_result res;
	fields(&h, ":method", "POST", ":scheme", "https", ":authority", "a", ":path", "/", "content-length", "5", NULL);
	ASSERT_EQ(check(&h, false, &r, &res), BST_PSEUDO_OK);
	ASSERT(res.has_length && res.length == 5);
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_MALFORMED); /* announces 5 bytes, ends the request */
	fields(&h, ":method", "POST", ":scheme", "https", ":authority", "a", ":path", "/", "content-length", "5",
	       "content-length", "6", NULL);
	ASSERT_EQ(check(&h, false, &r, &res), BST_PSEUDO_MALFORMED); /* two lengths that disagree */
	fields(&h, ":method", "POST", ":scheme", "https", ":authority", "a", ":path", "/", "content-length", "5",
	       "content-length", "5", NULL);
	ASSERT_EQ(check(&h, false, &r, &res), BST_PSEUDO_OK); /* the same number twice is one length */
	fields(&h, ":method", "POST", ":scheme", "https", ":authority", "a", ":path", "/", "content-length", "5x", NULL);
	ASSERT_EQ(check(&h, false, &r, &res), BST_PSEUDO_MALFORMED);
	fields(&h, ":method", "POST", ":scheme", "https", ":authority", "a", ":path", "/", "content-length", "-1", NULL);
	ASSERT_EQ(check(&h, false, &r, &res), BST_PSEUDO_MALFORMED);
	bst_arena_free(A);
}

TEST(cookie_crumbs)
{
	A = bst_arena_new(1 << 14);
	bst_headers h;
	bst_req_head r;
	bst_pseudo_result res;
	fields(&h, BASE, "cookie", "a=1", "accept", "*/*", "cookie", "b=2", "cookie", "c=3", NULL);
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_OK);
	const bst_header *c = bst_headers_get_name(&r.headers, BST_S("cookie"));
	ASSERT(c != NULL && bst_str_eq(c->value, BST_S("a=1; b=2; c=3"))); /* section 8.2.3 */
	int n = 0;
	for (uint32_t i = 0; i < r.headers.n; i++)
		if (bst_str_eq(r.headers.v[i].name, BST_S("cookie")))
			n++;
	ASSERT_EQ(n, 1);
	bst_arena_free(A);
}

TEST(authority_vs_host)
{
	A = bst_arena_new(1 << 14);
	bst_headers h;
	bst_req_head r;
	bst_pseudo_result res;
	fields(&h, BASE, "host", "example.test", NULL); /* they agree: fine, one Host remains */
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_OK);
	int n = 0;
	for (uint32_t i = 0; i < r.headers.n; i++)
		if (bst_str_eq(r.headers.v[i].name, BST_S("host")))
			n++;
	ASSERT_EQ(n, 1);
	fields(&h, BASE, "host", "evil.test", NULL); /* they disagree: a request that could be routed two ways */
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_BAD_REQUEST);
	fields(&h, ":method", "GET", ":scheme", "https", ":path", "/", "host", "only.test", NULL);
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_OK); /* Host alone stands for the authority */
	ASSERT(bst_str_eq(r.headers.v[r.headers.n - 1].value, BST_S("only.test")));
	fields(&h, ":method", "GET", ":scheme", "https", ":authority", "bad host", ":path", "/", NULL);
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_BAD_REQUEST); /* well-formed fields, unusable host */
	fields(&h, ":method", "GET", ":scheme", "https", ":authority", "a/b", ":path", "/", NULL);
	ASSERT_EQ(check(&h, true, &r, &res), BST_PSEUDO_BAD_REQUEST); /* userinfo-like or path text in it */
	bst_arena_free(A);
}

TAP_MAIN()

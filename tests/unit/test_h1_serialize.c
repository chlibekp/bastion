#include "http/h1/conn.h"
#include "tap.h"

#include <string.h>

static void init_head(bst_resp_head *h, bst_arena *a, int status, int64_t cl)
{
	memset(h, 0, sizeof *h);
	h->status = status;
	h->content_length = cl;
	bst_headers_init(&h->headers, a);
}

/* The serialized head as a NUL-terminated string living as long as the buffer. */
static const char *text(bst_buf *b)
{
	b->data[b->len] = '\0';
	return (const char *)b->data;
}

static bst_buf *ser(const bst_resp_head *h, bst_h1_head_opts o)
{
	return bst_h1_serialize_head(h, &o);
}

TEST(head_with_length)
{
	bst_arena *a = bst_arena_new(1024);
	bst_resp_head h;
	init_head(&h, a, 200, 5);
	ASSERT_EQ(bst_headers_add(&h.headers, BST_S("Content-Type"), BST_S("text/plain")), 0);
	bst_buf *b = ser(&h, (bst_h1_head_opts){ .server_tokens = false });
	ASSERT(b != NULL);
	const char *t = text(b);
	ASSERT(strncmp(t, "HTTP/1.1 200 OK\r\n", 17) == 0);
	ASSERT(strstr(t, "Content-Type: text/plain\r\n") != NULL);
	ASSERT(strstr(t, "Content-Length: 5\r\n") != NULL);
	ASSERT(strstr(t, "Server: bastion\r\n") != NULL);
	ASSERT(strstr(t, "Date: ") != NULL);
	ASSERT(strstr(t, "Connection:") == NULL);
	ASSERT(b->len >= 4 && memcmp(t + b->len - 4, "\r\n\r\n", 4) == 0);
	bst_buf_unref(b);
	bst_arena_free(a);
}

TEST(server_token_has_version)
{
	bst_arena *a = bst_arena_new(1024);
	bst_resp_head h;
	init_head(&h, a, 200, 0);
	bst_buf *b = ser(&h, (bst_h1_head_opts){ .server_tokens = true });
	ASSERT(b != NULL);
	ASSERT(strstr(text(b), "Server: bastion/") != NULL);
	bst_buf_unref(b);
	bst_arena_free(a);
}

TEST(chunked_close_keepalive)
{
	bst_arena *a = bst_arena_new(1024);
	bst_resp_head h;
	init_head(&h, a, 200, -1);
	bst_buf *b = ser(&h, (bst_h1_head_opts){ .chunked = true, .close = true });
	ASSERT(b != NULL);
	ASSERT(strstr(text(b), "Transfer-Encoding: chunked\r\n") != NULL);
	ASSERT(strstr(text(b), "Content-Length") == NULL);
	ASSERT(strstr(text(b), "Connection: close\r\n") != NULL);
	bst_buf_unref(b);
	b = ser(&h, (bst_h1_head_opts){ .keepalive = true });
	ASSERT(b != NULL);
	ASSERT(strstr(text(b), "Connection: keep-alive\r\n") != NULL);
	bst_buf_unref(b);
	bst_arena_free(a);
}

TEST(no_length_for_204)
{
	bst_arena *a = bst_arena_new(1024);
	bst_resp_head h;
	init_head(&h, a, 204, 0);
	bst_buf *b = ser(&h, (bst_h1_head_opts){ .omit_length = true });
	ASSERT(b != NULL);
	ASSERT(strncmp(text(b), "HTTP/1.1 204 No Content\r\n", 25) == 0);
	ASSERT(strstr(text(b), "Content-Length") == NULL);
	bst_buf_unref(b);
	bst_arena_free(a);
}

TEST(handler_cannot_set_framing)
{
	bst_arena *a = bst_arena_new(1024);
	bst_resp_head h;
	init_head(&h, a, 200, 3);
	ASSERT_EQ(bst_headers_add(&h.headers, BST_S("Content-Length"), BST_S("999")), 0);
	ASSERT_EQ(bst_headers_add(&h.headers, BST_S("Transfer-Encoding"), BST_S("chunked")), 0);
	ASSERT_EQ(bst_headers_add(&h.headers, BST_S("Connection"), BST_S("upgrade")), 0);
	ASSERT_EQ(bst_headers_add(&h.headers, BST_S("Date"), BST_S("Mon, 01 Jan 2024 00:00:00 GMT")), 0);
	bst_buf *b = ser(&h, (bst_h1_head_opts){ 0 });
	ASSERT(b != NULL);
	const char *t = text(b);
	ASSERT(strstr(t, "999") == NULL && strstr(t, "chunked") == NULL && strstr(t, "upgrade") == NULL);
	ASSERT(strstr(t, "Content-Length: 3\r\n") != NULL);
	ASSERT(strstr(t, "Date: Mon, 01 Jan 2024 00:00:00 GMT\r\n") != NULL); /* the handler's, once */
	ASSERT(strstr(strstr(t, "Date: ") + 6, "Date: ") == NULL);
	bst_buf_unref(b);
	bst_arena_free(a);
}

TEST(refuses_response_splitting)
{
	bst_arena *a = bst_arena_new(1024);
	bst_resp_head h;
	init_head(&h, a, 200, 0);
	ASSERT_EQ(bst_headers_add(&h.headers, BST_S("X-A"), (bst_str){ "v\r\nSet-Cookie: x", 16 }), 0);
	ASSERT(bst_h1_serialize_head(&h, &(bst_h1_head_opts){ 0 }) == NULL);
	init_head(&h, a, 200, 0);
	ASSERT_EQ(bst_headers_add(&h.headers, BST_S("X A"), BST_S("v")), 0);
	ASSERT(bst_h1_serialize_head(&h, &(bst_h1_head_opts){ 0 }) == NULL);
	init_head(&h, a, 200, 0);
	ASSERT_EQ(bst_headers_add(&h.headers, BST_S("X-A"), (bst_str){ "a\0b", 3 }), 0);
	ASSERT(bst_h1_serialize_head(&h, &(bst_h1_head_opts){ 0 }) == NULL);
	h.status = 99;
	ASSERT(bst_h1_serialize_head(&h, &(bst_h1_head_opts){ 0 }) == NULL);
	bst_arena_free(a);
}

TEST(interim)
{
	bst_buf *b = bst_h1_serialize_interim(100, NULL);
	ASSERT(b != NULL);
	ASSERT_STR(text(b), "HTTP/1.1 100 Continue\r\n\r\n");
	bst_buf_unref(b);
	ASSERT(bst_h1_serialize_interim(200, NULL) == NULL);
}

TEST(chunk_prefix)
{
	char out[24];
	ASSERT_EQ(bst_h1_chunk_prefix(out, 0), 3);
	ASSERT(memcmp(out, "0\r\n", 3) == 0);
	size_t n = bst_h1_chunk_prefix(out, 0xabcde);
	ASSERT(n == 7 && memcmp(out, "abcde\r\n", 7) == 0);
}

TEST(date_format)
{
	char out[BST_HTTP_DATE_LEN + 1];
	ASSERT_EQ(bst_http_date_format(784111777, out), BST_HTTP_DATE_LEN); /* RFC 9110's example */
	ASSERT_STR(out, "Sun, 06 Nov 1994 08:49:37 GMT");
	ASSERT_EQ(bst_http_date_format(0, out), BST_HTTP_DATE_LEN);
	ASSERT_STR(out, "Thu, 01 Jan 1970 00:00:00 GMT");
	/* leap day, century rule, a leap year that is a multiple of 400, and the last second of 9999 */
	ASSERT_EQ(bst_http_date_format(951782400, out), BST_HTTP_DATE_LEN);
	ASSERT_STR(out, "Tue, 29 Feb 2000 00:00:00 GMT");
	ASSERT_EQ(bst_http_date_format(1709251199, out), BST_HTTP_DATE_LEN);
	ASSERT_STR(out, "Thu, 29 Feb 2024 23:59:59 GMT");
	ASSERT_EQ(bst_http_date_format(253402300799, out), BST_HTTP_DATE_LEN);
	ASSERT_STR(out, "Fri, 31 Dec 9999 23:59:59 GMT");
	ASSERT_EQ(bst_http_date_format(-1, out), 0); /* out of range is refused, not wrapped */
	ASSERT_EQ(bst_http_date_format(253402300800, out), 0);
	bst_str d = bst_http_date();
	ASSERT_EQ(d.len, BST_HTTP_DATE_LEN);
}

TEST(reasons)
{
	ASSERT_STR(bst_http_reason(404), "Not Found");
	ASSERT_STR(bst_http_reason(431), "Request Header Fields Too Large");
	ASSERT_STR(bst_http_reason(299), "Unknown");
}

TEST(server_match)
{
	bst_cfg_server a = { 0 }, b = { 0 };
	const char *an[] = { "example.com" };
	a.names = an;
	a.nnames = 1;
	const bst_cfg_server *list[] = { &b, &a };
	bst_listener_set *set = bst_vhost_set_from(list, 2, &b);
	ASSERT(set != NULL);
	ASSERT(bst_vhost_select(set, BST_S("example.com")) == &a);
	ASSERT(bst_vhost_select(set, BST_S("EXAMPLE.com:8080")) == &a);
	ASSERT(bst_vhost_select(set, BST_S("other")) == &b);
	ASSERT(bst_vhost_select(set, (bst_str){ NULL, 0 }) == &b);
	bst_vhost_set_free(set);
}

TAP_MAIN()

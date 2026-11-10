#include "http/stream.h"

#include <stdio.h>
#include <string.h>

static const struct {
	int status;
	const char *reason;
} reasons[] = {
	{ 100, "Continue" }, { 101, "Switching Protocols" }, { 200, "OK" }, { 201, "Created" },
	{ 202, "Accepted" }, { 204, "No Content" }, { 206, "Partial Content" },
	{ 301, "Moved Permanently" }, { 302, "Found" }, { 303, "See Other" },
	{ 304, "Not Modified" }, { 307, "Temporary Redirect" }, { 308, "Permanent Redirect" },
	{ 400, "Bad Request" }, { 401, "Unauthorized" }, { 403, "Forbidden" }, { 404, "Not Found" },
	{ 405, "Method Not Allowed" }, { 408, "Request Timeout" }, { 409, "Conflict" },
	{ 411, "Length Required" }, { 412, "Precondition Failed" }, { 413, "Content Too Large" },
	{ 414, "URI Too Long" }, { 415, "Unsupported Media Type" }, { 416, "Range Not Satisfiable" },
	{ 417, "Expectation Failed" }, { 421, "Misdirected Request" }, { 429, "Too Many Requests" },
	{ 431, "Request Header Fields Too Large" }, { 500, "Internal Server Error" },
	{ 501, "Not Implemented" }, { 502, "Bad Gateway" }, { 503, "Service Unavailable" },
	{ 504, "Gateway Timeout" }, { 505, "HTTP Version Not Supported" },
};

const char *bst_http_reason(int status)
{
	for (size_t i = 0; i < sizeof reasons / sizeof reasons[0]; i++)
		if (reasons[i].status == status)
			return reasons[i].reason;
	return "Unknown";
}

/* Statuses that mean the request itself could not be read or trusted: the bytes that follow are
 * not a request boundary, so the connection ends. */
static bool closes(int status)
{
	switch (status) {
	case 400: case 408: case 413: case 414: case 431: case 501: case 505:
		return true;
	default:
		return false;
	}
}

int bst_send_error_hdr(bst_stream *s, int status, bst_str hname, bst_str hval)
{
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = status;
	h.close = closes(status);
	bst_headers_init(&h.headers, s->arena);

	bool has_body = status >= 200 && status != 204 && status != 304;
	char *page = NULL;
	int plen = 0;
	if (has_body) {
		const char *reason = bst_http_reason(status);
		size_t cap = 160 + 2 * strlen(reason);
		page = bst_arena_alloc(s->arena, cap);
		if (page == NULL)
			return -1;
		plen = snprintf(page, cap,
				"<html><head><title>%d %s</title></head>\r\n<body><center><h1>%d %s</h1></center>"
				"<hr><center>bastion</center></body></html>\r\n",
				status, reason, status, reason);
		if (plen < 0 || (size_t)plen >= cap)
			return -1;
		h.content_length = plen;
		if (bst_headers_add(&h.headers, BST_S("Content-Type"), BST_S("text/html; charset=utf-8")) != 0)
			return -1;
	} else {
		h.content_length = -1;
	}
	if (hname.len > 0 && bst_headers_add(&h.headers, hname, hval) != 0)
		return -1;
	if (bst_stream_send_head(s, &h, !has_body) != 0)
		return -1;
	if (!has_body)
		return 0;
	bst_buf *b = bst_buf_new((size_t)plen);
	if (b == NULL)
		return -1;
	memcpy(b->data, page, (size_t)plen);
	b->len = (size_t)plen;
	bst_chain *c = bst_arena_alloc(s->arena, sizeof *c);
	int rc = -1;
	if (c != NULL) {
		bst_chain_init(c, s->chain_slab);
		rc = bst_chain_add_mem(c, b, 0, b->len);
		if (rc == 0)
			rc = bst_stream_send_body(s, c, true, NULL, NULL);
	}
	bst_buf_unref(b);
	return rc;
}

int bst_send_error(bst_stream *s, int status)
{
	if (status == 405)
		return bst_send_error_hdr(s, status, BST_S("Allow"), BST_S(BST_ALLOWED_METHODS));
	return bst_send_error_hdr(s, status, (bst_str){ NULL, 0 }, (bst_str){ NULL, 0 });
}

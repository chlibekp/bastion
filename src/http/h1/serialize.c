#include "http/h1/conn.h"
#include "http/token.h"

#include <stdio.h>
#include <string.h>

#ifndef BST_VERSION
#define BST_VERSION "0.0.0"
#endif

typedef struct sb {
	char *p;
	size_t len, cap;
	bool bad;
} sb;

static void sb_put(sb *b, const char *s, size_t n)
{
	if (b->bad)
		return;
	if (b->len + n > b->cap) {
		b->bad = true;
		return;
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
}

#define PUT(b, lit) sb_put((b), (lit), sizeof(lit) - 1)

static bool framing_header(bst_hdr_id id)
{
	return id == BST_H_CONTENT_LENGTH || id == BST_H_TRANSFER_ENCODING || id == BST_H_CONNECTION ||
	       id == BST_H_KEEP_ALIVE;
}

/* Upper bound of the serialized size, or SIZE_MAX when a header is not fit to send. */
static size_t measure(const bst_headers *h)
{
	size_t n = 0;
	for (uint32_t i = 0; i < h->n; i++) {
		const bst_header *e = &h->v[i];
		if (!bst_is_token(e->name) || !bst_is_field_value_clean(e->value))
			return SIZE_MAX;
		n += (size_t)e->name.len + e->value.len + 4;
	}
	return n;
}

static void put_headers(sb *b, const bst_headers *h, bool *has_date, bool *has_server)
{
	for (uint32_t i = 0; i < h->n; i++) {
		const bst_header *e = &h->v[i];
		if (framing_header(e->id))
			continue;
		if (e->id == BST_H_DATE)
			*has_date = true;
		if (e->id == BST_H_SERVER)
			*has_server = true;
		sb_put(b, e->name.p, e->name.len);
		PUT(b, ": ");
		sb_put(b, e->value.p, e->value.len);
		PUT(b, "\r\n");
	}
}

static void put_status(sb *b, int status)
{
	char line[64];
	int n = snprintf(line, sizeof line, "HTTP/1.1 %d %s\r\n", status, bst_http_reason(status));
	if (n > 0)
		sb_put(b, line, (size_t)n);
}

bst_buf *bst_h1_serialize_head(const bst_resp_head *h, const bst_h1_head_opts *o)
{
	size_t hm = measure(&h->headers);
	if (hm == SIZE_MAX || h->status < 100 || h->status > 599)
		return NULL;
	size_t cap = 512 + hm;
	bst_buf *buf = bst_buf_new(cap);
	if (buf == NULL)
		return NULL;
	sb b = { (char *)buf->data, 0, cap, false };
	put_status(&b, h->status);
	bool has_date = false, has_server = false;
	put_headers(&b, &h->headers, &has_date, &has_server);
	if (!has_date) {
		bst_str d = bst_http_date();
		PUT(&b, "Date: ");
		sb_put(&b, d.p, d.len);
		PUT(&b, "\r\n");
	}
	if (!has_server) {
		if (o->server_tokens)
			PUT(&b, "Server: bastion/" BST_VERSION "\r\n");
		else
			PUT(&b, "Server: bastion\r\n");
	}
	if (o->chunked) {
		PUT(&b, "Transfer-Encoding: chunked\r\n");
	} else if (!o->omit_length && h->content_length >= 0) {
		char line[48];
		int n = snprintf(line, sizeof line, "Content-Length: %lld\r\n", (long long)h->content_length);
		if (n > 0)
			sb_put(&b, line, (size_t)n);
	}
	if (o->close)
		PUT(&b, "Connection: close\r\n");
	else if (o->keepalive)
		PUT(&b, "Connection: keep-alive\r\n");
	PUT(&b, "\r\n");
	if (b.bad) {
		bst_buf_unref(buf);
		return NULL;
	}
	buf->len = b.len;
	return buf;
}

bst_buf *bst_h1_serialize_interim(int status, const bst_headers *h)
{
	size_t hm = h != NULL ? measure(h) : 0;
	if (hm == SIZE_MAX || status < 100 || status > 199)
		return NULL;
	size_t cap = 64 + hm;
	bst_buf *buf = bst_buf_new(cap);
	if (buf == NULL)
		return NULL;
	sb b = { (char *)buf->data, 0, cap, false };
	put_status(&b, status);
	bool d = false, s = false;
	if (h != NULL)
		put_headers(&b, h, &d, &s);
	PUT(&b, "\r\n");
	if (b.bad) {
		bst_buf_unref(buf);
		return NULL;
	}
	buf->len = b.len;
	return buf;
}

size_t bst_h1_chunk_prefix(char out[24], size_t n)
{
	int k = snprintf(out, 24, "%zx\r\n", n);
	return k > 0 ? (size_t)k : 0;
}

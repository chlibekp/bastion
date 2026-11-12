/* See client_h1.h. */
#include "proxy/client_h1.h"

#include "http/token.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { ST_HEAD, ST_BODY, ST_DONE, ST_ERROR };

/* ---- request head ---- */

static bool target_ok(bst_str t)
{
	if (t.len == 0)
		return false;
	for (size_t i = 0; i < t.len; i++) {
		unsigned char c = (unsigned char)t.p[i];
		if (c <= 0x20 || c == 0x7f)
			return false; /* a space or control byte would end or split the request line */
	}
	return true;
}

static void put(char **w, bst_str s)
{
	memcpy(*w, s.p, s.len);
	*w += s.len;
}

bst_buf *bst_h1_req_head(const bst_h1_req_out *r)
{
	if (!bst_is_token(r->method) || !target_ok(r->target) || !bst_is_field_value_clean(r->host) ||
	    r->host.len == 0)
		return NULL;
	size_t n = r->method.len + 1 + r->target.len + 11 + 6 + r->host.len + 2 + 2;
	for (uint32_t i = 0; i < r->headers->n; i++) {
		const bst_header *h = &r->headers->v[i];
		if (!bst_is_token(h->name) || !bst_is_field_value_clean(h->value))
			return NULL;
		n += h->name.len + 2 + h->value.len + 2;
	}
	n += 64; /* Content-Length or Transfer-Encoding */
	bst_buf *b = bst_buf_new(n);
	if (b == NULL)
		return NULL;
	char *w = (char *)b->data;
	put(&w, r->method);
	*w++ = ' ';
	put(&w, r->target);
	put(&w, BST_S(" HTTP/1.1\r\nHost: "));
	put(&w, r->host);
	put(&w, BST_S("\r\n"));
	for (uint32_t i = 0; i < r->headers->n; i++) {
		const bst_header *h = &r->headers->v[i];
		put(&w, h->name);
		put(&w, BST_S(": "));
		put(&w, h->value);
		put(&w, BST_S("\r\n"));
	}
	if (r->chunked)
		put(&w, BST_S("Transfer-Encoding: chunked\r\n"));
	else if (r->has_length)
		w += snprintf(w, 48, "Content-Length: %" PRIu64 "\r\n", r->length);
	put(&w, BST_S("\r\n"));
	b->len = (size_t)(w - (char *)b->data);
	return b;
}

/* ---- response reader ---- */

void bst_h1_client_init(bst_h1_client *c, bst_arena *arena, size_t max_head, bool head_req,
			const bst_h1_body_cfg *bcfg)
{
	memset(c, 0, sizeof *c);
	c->arena = arena;
	c->max_head = max_head;
	c->head_req = head_req;
	c->bcfg = *bcfg;
	c->bcfg.max_body = 0; /* the upstream's body is not limited here */
	bst_h1_resp_parser_init(&c->p, arena);
	bst_headers_init(&c->trailers, arena);
}

void bst_h1_client_free(bst_h1_client *c)
{
	free(c->hbuf);
	c->hbuf = NULL;
	c->hlen = c->hcap = 0;
}

static bst_upc_ev feed_head(bst_h1_client *c, bst_buf *in, size_t *off)
{
	size_t avail = in->len - *off;
	size_t room = c->max_head - c->hlen;
	size_t take = avail < room ? avail : room;
	if (c->hlen + take > c->hcap) {
		size_t cap = c->hcap ? c->hcap : 1024;
		while (cap < c->hlen + take)
			cap *= 2;
		if (cap > c->max_head)
			cap = c->max_head;
		char *nb = realloc(c->hbuf, cap);
		if (nb == NULL) {
			c->st = ST_ERROR;
			return BST_UPC_ERROR;
		}
		c->hbuf = nb;
		c->hcap = cap;
	}
	size_t prev = c->hlen;
	memcpy(c->hbuf + c->hlen, in->data + *off, take);
	c->hlen += take;
	bst_h1_result r = bst_h1_parse_resp_head(&c->p, c->hbuf, c->hlen, c->max_head, &c->head);
	if (r.kind == BST_H1_NEED_MORE) {
		*off += take;
		return BST_UPC_MORE;
	}
	if (r.kind == BST_H1_ERROR) {
		c->st = ST_ERROR;
		return BST_UPC_ERROR;
	}
	*off += r.consumed - prev; /* the head ended inside this read */
	c->hlen = 0;
	bst_h1_resp_parser_init(&c->p, c->arena);
	if (bst_h1_resp_framing_of(&c->head, c->head_req, &c->fr) != 0) {
		c->st = ST_ERROR;
		return BST_UPC_ERROR;
	}
	if (c->head.status >= 100 && c->head.status < 200 && c->head.status != 101)
		return BST_UPC_INTERIM; /* stay in ST_HEAD for the final response */
	switch (c->fr.kind) {
	case BST_RESP_BODY_NONE:
		c->st = ST_DONE;
		break;
	case BST_RESP_BODY_LENGTH:
		c->st = c->fr.length == 0 ? ST_DONE : ST_BODY;
		bst_h1_body_init(&c->body, (bst_framing){ BST_FRAMING_LENGTH, c->fr.length },
				 &c->bcfg, c->arena);
		break;
	case BST_RESP_BODY_CHUNKED:
		c->st = ST_BODY;
		bst_h1_body_init(&c->body, (bst_framing){ BST_FRAMING_CHUNKED, 0 }, &c->bcfg,
				 c->arena);
		break;
	case BST_RESP_BODY_CLOSE:
		c->st = ST_BODY;
		break;
	}
	return BST_UPC_HEAD;
}

bst_upc_ev bst_h1_client_feed(bst_h1_client *c, bst_buf *in, size_t *off, bst_chain *out)
{
	if (*off < in->len)
		c->got_bytes = true;
	switch (c->st) {
	case ST_HEAD:
		if (*off >= in->len)
			return BST_UPC_MORE;
		return feed_head(c, in, off);
	case ST_BODY: {
		if (*off >= in->len)
			return BST_UPC_MORE;
		if (c->fr.kind == BST_RESP_BODY_CLOSE) {
			size_t n = in->len - *off;
			if (bst_chain_add_mem(out, in, *off, n) != 0) {
				c->st = ST_ERROR;
				return BST_UPC_ERROR;
			}
			*off = in->len;
			c->body_bytes += n;
			return BST_UPC_BODY;
		}
		uint64_t before = bst_chain_len(out);
		int status = 0;
		bst_h1_body_kind k = bst_h1_body_feed(&c->body, in, off, out, &c->trailers, &status);
		c->body_bytes += bst_chain_len(out) - before;
		if (k == BST_H1_BODY_ERROR) {
			c->st = ST_ERROR;
			return BST_UPC_ERROR;
		}
		if (k == BST_H1_BODY_DONE) {
			c->st = ST_DONE;
			return BST_UPC_DONE;
		}
		return bst_chain_len(out) > before ? BST_UPC_BODY : BST_UPC_MORE;
	}
	case ST_DONE:
		return BST_UPC_DONE;
	default:
		return BST_UPC_ERROR;
	}
}

bst_upc_ev bst_h1_client_eof(bst_h1_client *c)
{
	if (c->st == ST_DONE)
		return BST_UPC_DONE;
	if (c->st == ST_BODY && c->fr.kind == BST_RESP_BODY_CLOSE) {
		c->st = ST_DONE;
		return BST_UPC_DONE;
	}
	c->st = ST_ERROR;
	return BST_UPC_ERROR;
}

bool bst_h1_client_reusable(const bst_h1_client *c)
{
	return c->st == ST_DONE && c->fr.keepalive;
}

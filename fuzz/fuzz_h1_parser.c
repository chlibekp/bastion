/* libFuzzer harness for the HTTP/1.1 request head parser. The first input byte is a flag set
 * (bit 0: read every LF as CRLF, so a seed can be plain text; bit 1: http1_allow_bare_lf; bit 2:
 * small limits, so 414 and 431 are reachable), the rest is the request.
 *
 * Properties: no crash or sanitizer report; the answer is the same whether the bytes arrive
 * whole, cut in two or one at a time (the parser must not depend on read boundaries); a DONE
 * head obeys the grammar it promises (method a token, no control byte in the target or in
 * any value, names tokens, at most max_headers of them) and consumed lies inside the input. */
#include "http/h1/parser.h"
#include "http/token.h"

#include <stdlib.h>
#include <string.h>

static bool same(const bst_h1_result *a, const bst_req_head *ha, const bst_h1_result *b,
		 const bst_req_head *hb)
{
	if (a->kind != b->kind || a->status != b->status || a->consumed != b->consumed)
		return false;
	if (a->kind != BST_H1_DONE)
		return true;
	if (ha->method != hb->method || ha->form != hb->form || ha->headers.n != hb->headers.n ||
	    ha->version_minor != hb->version_minor || !bst_str_eq(ha->target, hb->target) ||
	    !bst_str_eq(ha->path, hb->path) || !bst_str_eq(ha->query, hb->query) ||
	    !bst_str_eq(ha->authority, hb->authority))
		return false;
	for (uint32_t i = 0; i < ha->headers.n; i++)
		if (!bst_str_eq(ha->headers.v[i].name, hb->headers.v[i].name) ||
		    !bst_str_eq(ha->headers.v[i].value, hb->headers.v[i].value))
			return false;
	return true;
}

static bst_h1_result run(const char *buf, size_t n, size_t cut, bool bytewise,
			 const bst_h1_limits *lim, bst_req_head *h, bst_arena *a)
{
	bst_h1_parser p;
	bst_h1_parser_init(&p, a);
	bst_h1_result r = { .kind = BST_H1_NEED_MORE };
	if (bytewise) {
		for (size_t len = 1; len <= n && r.kind == BST_H1_NEED_MORE; len++)
			r = bst_h1_parse_head(&p, buf, len, lim, h);
		return r;
	}
	if (cut > n)
		cut = n;
	if (cut > 0)
		r = bst_h1_parse_head(&p, buf, cut, lim, h);
	if (r.kind == BST_H1_NEED_MORE)
		r = bst_h1_parse_head(&p, buf, n, lim, h);
	return r;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size < 1)
		return 0;
	uint8_t flags = d[0];
	const uint8_t *in = d + 1;
	size_t inlen = size - 1;
	char *buf = malloc(inlen * 2 + 1);
	if (buf == NULL)
		abort();
	size_t n = 0;
	for (size_t i = 0; i < inlen; i++) {
		if ((flags & 1) && in[i] == '\n')
			buf[n++] = '\r';
		buf[n++] = (char)in[i];
	}
	bst_h1_limits lim = { .max_uri = 8192, .max_head = 16384, .max_headers = 100,
			      .allow_bare_lf = (flags & 2) != 0 };
	if (flags & 4)
		lim = (bst_h1_limits){ .max_uri = 24, .max_head = 150, .max_headers = 4,
				       .allow_bare_lf = lim.allow_bare_lf };

	bst_arena *a0 = bst_arena_new(4096);
	bst_req_head whole;
	bst_h1_result w = run(buf, n, 0, false, &lim, &whole, a0);

	if (w.kind == BST_H1_DONE) {
		if (w.consumed == 0 || w.consumed > n || whole.headers.n > lim.max_headers ||
		    whole.target.len == 0 || whole.target.len > lim.max_uri || w.consumed > lim.max_head)
			abort();
		if (!bst_is_token(whole.method_str))
			abort();
		for (uint32_t i = 0; i < whole.target.len; i++)
			if ((unsigned char)whole.target.p[i] <= 0x20 || (unsigned char)whole.target.p[i] >= 0x7f)
				abort();
		for (uint32_t i = 0; i < whole.headers.n; i++)
			if (!bst_is_token(whole.headers.v[i].name) ||
			    !bst_is_field_value_clean(whole.headers.v[i].value))
				abort();
	}

	size_t cuts[4] = { 1, n / 3, n / 2, n > 0 ? n - 1 : 0 };
	for (int k = 0; k < 4; k++) {
		bst_arena *a = bst_arena_new(4096);
		bst_req_head h;
		bst_h1_result r = run(buf, n, cuts[k], false, &lim, &h, a);
		if (!same(&w, &whole, &r, &h))
			abort();
		bst_arena_free(a);
	}
	if (n <= 400) {
		bst_arena *a = bst_arena_new(4096);
		bst_req_head h;
		bst_h1_result r = run(buf, n, 0, true, &lim, &h, a);
		if (!same(&w, &whole, &r, &h))
			abort();
		bst_arena_free(a);
	}
	bst_arena_free(a0);
	free(buf);
	return 0;
}

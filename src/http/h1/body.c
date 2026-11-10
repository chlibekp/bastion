#include "http/h1/body.h"

#include "http/token.h"

#include <string.h>

enum {
	S_LENGTH, /* Content-Length data */
	S_SIZE,	  /* chunk-size digits */
	S_EXT,	  /* chunk extension bytes up to the CR */
	S_SIZE_LF, /* the CR after the size line was seen */
	S_DATA,
	S_DATA_CR,
	S_DATA_LF,
	S_TRAIL_START, /* start of a trailer line, or of the final empty line */
	S_TRAIL_LINE,  /* inside a trailer line */
	S_TRAIL_LINE_CR,
	S_END_LF, /* the CR of the final empty line was seen */
	S_DONE,
	S_ERR,
};

void bst_h1_body_init(bst_h1_body *b, bst_framing framing, const bst_h1_body_cfg *cfg,
		      bst_arena *arena)
{
	*b = (bst_h1_body){ .framing = framing, .cfg = *cfg, .arena = arena };
	switch (framing.kind) {
	case BST_FRAMING_NONE:
		b->st = S_DONE;
		break;
	case BST_FRAMING_LENGTH:
		b->st = S_LENGTH;
		b->remaining = framing.length;
		break;
	case BST_FRAMING_CHUNKED:
		b->st = S_SIZE;
		break;
	}
}

static bst_h1_body_kind fail(bst_h1_body *b, int status, int *out)
{
	b->st = S_ERR;
	b->err = status;
	*out = status;
	return BST_H1_BODY_ERROR;
}

/* ---- trailers ---- */

bool bst_h1_trailer_forbidden(bst_str name)
{
	switch (bst_hdr_lookup(name.p, name.len)) {
	case BST_H_CONTENT_LENGTH: case BST_H_TRANSFER_ENCODING: case BST_H_TE: case BST_H_TRAILER:
	case BST_H_HOST: case BST_H_EXPECT: case BST_H_MAX_FORWARDS: case BST_H_RANGE:
	case BST_H_IF_MATCH: case BST_H_IF_NONE_MATCH: case BST_H_IF_MODIFIED_SINCE:
	case BST_H_IF_UNMODIFIED_SINCE: case BST_H_IF_RANGE: case BST_H_CACHE_CONTROL:
	case BST_H_PRAGMA: case BST_H_AUTHORIZATION: case BST_H_PROXY_AUTHORIZATION:
	case BST_H_COOKIE: case BST_H_SET_COOKIE: case BST_H_CONTENT_TYPE:
	case BST_H_CONTENT_ENCODING: case BST_H_CONTENT_RANGE: case BST_H_CONNECTION:
	case BST_H_UPGRADE: case BST_H_KEEP_ALIVE:
		return true;
	default:
		return false;
	}
}

/* Parses the collected trailer section (lines ending CRLF, then nothing). 0 or 400. */
static int parse_trailers(bst_h1_body *b, bst_headers *out)
{
	if (b->tlen == 0)
		return 0; /* no trailer section: tbuf was never allocated */
	const char *p = b->tbuf, *end = b->tbuf + b->tlen;
	while (p < end) {
		const char *eol = memchr(p, '\n', (size_t)(end - p));
		if (eol == NULL || eol == p || eol[-1] != '\r')
			return 400; /* a bare LF */
		const char *line_end = eol - 1;
		if (*p == ' ' || *p == '\t') /* obsolete line folding */
			return 400;
		const char *colon = memchr(p, ':', (size_t)(line_end - p));
		if (colon == NULL || colon == p)
			return 400;
		bst_str name = { p, (uint32_t)(colon - p) };
		if (!bst_is_token(name)) /* a space before the colon lands here */
			return 400;
		const char *v = colon + 1, *ve = line_end;
		while (v < ve && (*v == ' ' || *v == '\t'))
			v++;
		while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t'))
			ve--;
		bst_str value = { v, (uint32_t)(ve - v) };
		if (!bst_is_field_value_clean(value))
			return 400;
		if (out != NULL && !bst_h1_trailer_forbidden(name))
			if (bst_headers_add(out, name, value) != 0)
				return 500;
		p = eol + 1;
	}
	return 0;
}

static int hexval(unsigned char c)
{
	return c >= '0' && c <= '9' ? c - '0' : (c | 32) >= 'a' && (c | 32) <= 'f' ? (c | 32) - 'a' + 10 : -1;
}

bst_h1_body_kind bst_h1_body_feed(bst_h1_body *b, bst_buf *in, size_t *off, bst_chain *out,
				  bst_headers *trailers, int *status)
{
	if (b->st == S_ERR)
		return fail(b, b->err, status);
	if (b->st == S_DONE)
		return BST_H1_BODY_DONE;
	const unsigned char *d = in->data;
	size_t i = *off, n = in->len;

	if (b->st == S_LENGTH && b->cfg.max_body != 0 && b->framing.length > b->cfg.max_body)
		return fail(b, 413, status);

	while (i < n) {
		unsigned char c = d[i];
		switch (b->st) {
		case S_LENGTH:
		case S_DATA: {
			uint64_t avail = n - i, take = b->remaining < avail ? b->remaining : avail;
			if (bst_chain_add_mem(out, in, i, (size_t)take) != 0)
				return fail(b, 500, status);
			b->total += take;
			b->remaining -= take;
			i += (size_t)take;
			if (b->remaining == 0)
				b->st = b->st == S_LENGTH ? S_DONE : S_DATA_CR;
			break;
		}
		case S_SIZE:
			if (hexval(c) >= 0) {
				if (b->chunk > (UINT64_MAX >> 4))
					return fail(b, 400, status); /* sixteen digits and one more */
				b->chunk = b->chunk << 4 | (uint64_t)hexval(c);
				b->digits++;
				i++;
			} else if (b->digits == 0) {
				return fail(b, 400, status); /* no digit at all */
			} else if (c == ';') {
				b->ext_len = 0;
				b->st = S_EXT;
				i++;
			} else if (c == '\r') {
				b->st = S_SIZE_LF;
				i++;
			} else {
				return fail(b, 400, status); /* a space, a sign, a bare LF, anything else */
			}
			break;
		case S_EXT:
			if (c == '\r') {
				b->st = S_SIZE_LF;
			} else if ((c < 0x20 && c != '\t') || c == 0x7f || ++b->ext_len > b->cfg.chunk_ext_limit) {
				return fail(b, 400, status);
			}
			i++;
			break;
		case S_SIZE_LF:
			if (c != '\n')
				return fail(b, 400, status);
			i++;
			if (b->chunk == 0) {
				b->st = S_TRAIL_START;
			} else {
				if (b->cfg.max_body != 0 &&
				    (b->chunk > b->cfg.max_body || b->total > b->cfg.max_body - b->chunk))
					return fail(b, 413, status);
				b->remaining = b->chunk;
				b->st = S_DATA;
			}
			b->chunk = 0;
			b->digits = 0;
			b->ext_len = 0;
			break;
		case S_DATA_CR:
			if (c != '\r')
				return fail(b, 400, status); /* data that outruns its chunk size */
			b->st = S_DATA_LF;
			i++;
			break;
		case S_DATA_LF:
			if (c != '\n')
				return fail(b, 400, status);
			b->st = S_SIZE;
			i++;
			break;
		case S_TRAIL_START:
			if (c == '\r') {
				b->st = S_END_LF;
				i++;
				break;
			}
			__attribute__((fallthrough)); /* the first byte of a trailer line */
		case S_TRAIL_LINE:
		case S_TRAIL_LINE_CR:
			if (b->tbuf == NULL) {
				b->tcap = b->cfg.max_trailer;
				b->tbuf = b->tcap ? bst_arena_alloc(b->arena, b->tcap) : NULL;
				if (b->tbuf == NULL)
					return fail(b, 431, status);
			}
			if (b->tlen >= b->tcap)
				return fail(b, 431, status);
			b->tbuf[b->tlen++] = (char)c;
			i++;
			if (b->st == S_TRAIL_LINE_CR) {
				if (c != '\n')
					return fail(b, 400, status); /* a bare CR */
				b->st = S_TRAIL_START;
			} else if (c == '\r') {
				b->st = S_TRAIL_LINE_CR;
			} else {
				b->st = S_TRAIL_LINE;
			}
			break;
		case S_END_LF: {
			if (c != '\n')
				return fail(b, 400, status);
			i++;
			*off = i;
			int st = parse_trailers(b, trailers);
			if (st != 0)
				return fail(b, st, status);
			b->st = S_DONE;
			return BST_H1_BODY_DONE;
		}
		case S_DONE:
			*off = i;
			return BST_H1_BODY_DONE;
		default:
			return fail(b, 500, status);
		}
		if (b->st == S_DONE) {
			*off = i;
			return BST_H1_BODY_DONE;
		}
	}
	*off = i;
	return BST_H1_BODY_MORE;
}

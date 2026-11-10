#include "http/h1/parser.h"

#include "http/h1/scan.h"
#include "http/semantics.h"
#include "http/token.h"

#include <string.h>

enum {
	S_START,    /* before the request line: empty lines are skipped */
	S_START_LF, /* the CR of such an empty line was seen */
	S_METHOD,
	S_TARGET,
	S_VERSION,
	S_REQ_LF, /* the CR ending the request line was seen */
	S_HDR_START,
	S_HDR_END_LF, /* the CR of the empty line ending the head was seen */
	S_NAME,
	S_VALUE_WS,
	S_VALUE,
	S_VALUE_LF, /* the CR ending a header line was seen */
	S_DONE,
	S_ERR,
};

void bst_h1_parser_init(bst_h1_parser *p, bst_arena *arena)
{
	*p = (bst_h1_parser){ .arena = arena, .st = S_START };
}

static bst_h1_result fail(bst_h1_parser *p, int status)
{
	p->st = S_ERR;
	p->err = status;
	return (bst_h1_result){ .kind = BST_H1_ERROR, .status = status };
}

/* ---- request-target (RFC 9112 section 3.2) ---- */

/* Splits path and query off rest (which starts at the path or the query); false on '#'. */
static bool path_query(bst_req_head *h, bst_str rest)
{
	if (memchr(rest.p, '#', rest.len) != NULL) /* a fragment never reaches a server */
		return false;
	const char *q = memchr(rest.p, '?', rest.len);
	size_t plen = q ? (size_t)(q - rest.p) : rest.len;
	h->path = (bst_str){ rest.p, (uint32_t)plen };
	if (q) {
		h->has_query = true;
		h->query = (bst_str){ q + 1, (uint32_t)(rest.len - plen - 1) };
	}
	if (h->path.len == 0 && h->form == BST_TARGET_ABSOLUTE)
		h->path = BST_S("/");
	return true;
}

/* 0, or the status to answer with. */
static int parse_target(bst_req_head *h, bst_str t)
{
	h->target = t;
	if (h->method == BST_M_CONNECT) {
		h->form = BST_TARGET_AUTHORITY;
		if (!bst_valid_authority(t, true))
			return 400;
		h->authority = t;
		return 0;
	}
	if (t.p[0] == '/') {
		h->form = BST_TARGET_ORIGIN;
		return path_query(h, t) ? 0 : 400;
	}
	if (t.len == 1 && t.p[0] == '*') {
		h->form = BST_TARGET_ASTERISK;
		return h->method == BST_M_OPTIONS ? 0 : 400;
	}
	/* absolute-form: scheme "://" authority [path] [? query] */
	size_t i = 0;
	if (!(((t.p[0] | 32) >= 'a') && ((t.p[0] | 32) <= 'z')))
		return 400;
	while (i < t.len && (((t.p[i] | 32) >= 'a' && (t.p[i] | 32) <= 'z') ||
			     (t.p[i] >= '0' && t.p[i] <= '9') || t.p[i] == '+' || t.p[i] == '-' ||
			     t.p[i] == '.'))
		i++;
	if (i + 3 > t.len || memcmp(t.p + i, "://", 3) != 0)
		return 400;
	h->form = BST_TARGET_ABSOLUTE;
	h->scheme = (bst_str){ t.p, (uint32_t)i };
	size_t a0 = i + 3, a1 = a0;
	while (a1 < t.len && t.p[a1] != '/' && t.p[a1] != '?' && t.p[a1] != '#')
		a1++;
	h->authority = (bst_str){ t.p + a0, (uint32_t)(a1 - a0) };
	if (!bst_valid_authority(h->authority, false))
		return 400;
	return path_query(h, (bst_str){ t.p + a1, (uint32_t)(t.len - a1) }) ? 0 : 400;
}

/* ---- the head is complete ---- */

static bst_h1_result finish(bst_h1_parser *p, const char *buf, size_t consumed, bst_req_head *out)
{
	char *mem = bst_arena_alloc(p->arena, consumed ? consumed : 1);
	if (mem == NULL)
		return fail(p, 500);
	memcpy(mem, buf, consumed);
	memset(out, 0, sizeof *out);
	out->method_str = (bst_str){ mem + p->m_off, p->m_len };
	out->method = bst_method_from(out->method_str);
	out->version_minor = p->minor >= 1 ? 1 : 0;
	int st = parse_target(out, (bst_str){ mem + p->t_off, p->t_len });
	if (st != 0)
		return fail(p, st);
	bst_headers_init(&out->headers, p->arena);
	if (p->nent > 0) {
		out->headers.v = bst_arena_alloc(p->arena, (size_t)p->nent * sizeof *out->headers.v);
		if (out->headers.v == NULL)
			return fail(p, 500);
		out->headers.cap = p->nent;
	}
	for (uint32_t k = 0; k < p->nent; k++) {
		const bst_h1_hent *e = &p->ents[k];
		(void)bst_headers_add(&out->headers, (bst_str){ mem + e->name_off, e->name_len },
				      (bst_str){ mem + e->val_off, e->val_len });
	}
	p->st = S_DONE;
	return (bst_h1_result){ .kind = BST_H1_DONE, .consumed = consumed };
}

static int push_header(bst_h1_parser *p, const char *buf, size_t line_end, size_t max_headers)
{
	if (p->nent >= max_headers)
		return 431;
	size_t ve = line_end;
	while (ve > p->v_off && (buf[ve - 1] == ' ' || buf[ve - 1] == '\t'))
		ve--;
	if (p->nent == p->cap) {
		uint32_t cap = p->cap ? p->cap * 2 : 16;
		bst_h1_hent *n = bst_arena_alloc(p->arena, (size_t)cap * sizeof *n);
		if (n == NULL)
			return 500;
		if (p->nent > 0)
			memcpy(n, p->ents, (size_t)p->nent * sizeof *n);
		p->ents = n;
		p->cap = cap;
	}
	p->ents[p->nent++] = (bst_h1_hent){ p->n_off, p->n_len, p->v_off, (uint32_t)(ve - p->v_off) };
	return 0;
}

bst_h1_result bst_h1_parse_head(bst_h1_parser *p, const char *buf, size_t len,
				const bst_h1_limits *lim, bst_req_head *out)
{
	if (p->st == S_ERR)
		return fail(p, p->err);
	if (p->st == S_DONE || len < p->pos)
		return fail(p, 500); /* the caller broke the contract: never silently continue */
	/* Only the first max_head bytes may be part of the head; a byte beyond them is an error
	 * unless the head ended before it. */
	size_t end = len > lim->max_head ? lim->max_head : len;
	bool capped = len > lim->max_head;
	size_t i = p->pos;
	static const char version[] = "HTTP/";

	for (;;) {
		if (i >= end) {
			if (capped)
				return fail(p, 431);
			p->pos = i;
			return (bst_h1_result){ .kind = BST_H1_NEED_MORE };
		}
		unsigned char c = (unsigned char)buf[i];
		switch (p->st) {
		case S_START:
			if (c == '\r' || c == '\n') {
				if (++p->leading > BST_H1_MAX_LEADING_EMPTY)
					return fail(p, 400);
				if (c == '\n' && !lim->allow_bare_lf)
					return fail(p, 400);
				p->st = c == '\r' ? S_START_LF : S_START;
				i++;
				break;
			}
			p->m_off = (uint32_t)i;
			p->st = S_METHOD;
			break;
		case S_START_LF:
			if (c != '\n')
				return fail(p, 400);
			p->st = S_START;
			i++;
			break;
		case S_METHOD:
			while (i < end && bst_is_tchar((unsigned char)buf[i])) {
				if (i - p->m_off >= BST_H1_MAX_METHOD)
					return fail(p, 501);
				i++;
			}
			if (i >= end)
				break; /* the top of the loop decides */
			if (buf[i] != ' ' || i == p->m_off)
				return fail(p, 400);
			p->m_len = (uint32_t)(i - p->m_off);
			i++;
			p->t_off = (uint32_t)i;
			p->st = S_TARGET;
			break;
		case S_TARGET: {
			size_t left = lim->max_uri - p->t_len; /* t_len <= max_uri always */
			size_t room = end - i < left + 1 ? end - i : left + 1;
			size_t run = bst_h1_scan_target(buf + i, room);
			p->t_len += (uint32_t)run;
			i += run;
			if (p->t_len > lim->max_uri)
				return fail(p, 414);
			if (i >= end)
				break;
			if (buf[i] != ' ' || p->t_len == 0)
				return fail(p, 400);
			i++;
			p->st = S_VERSION;
			break;
		}
		case S_VERSION:
			if (p->ver_i < 5) {
				if (c != (unsigned char)version[p->ver_i])
					return fail(p, 400);
			} else if (p->ver_i == 5) {
				if (c < '0' || c > '9')
					return fail(p, 400);
				p->major = (uint8_t)(c - '0');
			} else if (p->ver_i == 6) {
				if (c != '.')
					return fail(p, 400);
			} else if (p->ver_i == 7) {
				if (c < '0' || c > '9')
					return fail(p, 400);
				p->minor = (uint8_t)(c - '0');
				if (p->major != 1)
					return fail(p, 505);
			} else { /* the line ends right after the version */
				if (c == '\r')
					p->st = S_REQ_LF;
				else if (c == '\n' && lim->allow_bare_lf)
					p->st = S_HDR_START;
				else
					return fail(p, 400);
				i++;
				break;
			}
			p->ver_i++;
			i++;
			break;
		case S_REQ_LF:
			if (c != '\n')
				return fail(p, 400);
			p->st = S_HDR_START;
			i++;
			break;
		case S_HDR_START:
			if (c == '\r') {
				p->st = S_HDR_END_LF;
				i++;
			} else if (c == '\n') {
				if (!lim->allow_bare_lf)
					return fail(p, 400);
				return finish(p, buf, i + 1, out);
			} else if (bst_is_tchar(c)) {
				p->n_off = (uint32_t)i;
				p->st = S_NAME;
			} else {
				return fail(p, 400); /* obs-fold, a space, a colon or a control byte */
			}
			break;
		case S_HDR_END_LF:
			if (c != '\n')
				return fail(p, 400);
			return finish(p, buf, i + 1, out);
		case S_NAME:
			while (i < end && bst_is_tchar((unsigned char)buf[i]))
				i++;
			if (i >= end)
				break;
			if (buf[i] != ':') /* a space before the colon lands here */
				return fail(p, 400);
			p->n_len = (uint32_t)(i - p->n_off);
			i++;
			p->st = S_VALUE_WS;
			break;
		case S_VALUE_WS:
			while (i < end && (buf[i] == ' ' || buf[i] == '\t'))
				i++;
			if (i >= end)
				break;
			p->v_off = (uint32_t)i;
			p->st = S_VALUE;
			break;
		case S_VALUE:
			i += bst_h1_scan_value(buf + i, end - i);
			if (i >= end)
				break;
			if (buf[i] == '\r') {
				int st = push_header(p, buf, i, lim->max_headers);
				if (st != 0)
					return fail(p, st);
				p->st = S_VALUE_LF;
				i++;
			} else if (buf[i] == '\n' && lim->allow_bare_lf) {
				int st = push_header(p, buf, i, lim->max_headers);
				if (st != 0)
					return fail(p, st);
				p->st = S_HDR_START;
				i++;
			} else {
				return fail(p, 400); /* NUL, another control byte, or a bare LF */
			}
			break;
		case S_VALUE_LF:
			if (c != '\n')
				return fail(p, 400); /* a bare CR */
			p->st = S_HDR_START;
			i++;
			break;
		default:
			return fail(p, 500);
		}
	}
}

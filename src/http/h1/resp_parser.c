/* See resp_parser.h. */
#include "http/h1/resp_parser.h"

#include "http/token.h"

#include <string.h>

void bst_h1_resp_parser_init(bst_h1_resp_parser *p, bst_arena *arena)
{
	p->arena = arena;
	p->scanned = 0;
}

static bool is_vchar_or_ws(unsigned char c)
{
	return c == '\t' || c == ' ' || (c >= 0x21 && c != 0x7f);
}

static bst_h1_result err502(void)
{
	return (bst_h1_result){ .kind = BST_H1_ERROR, .status = 502 };
}

/* Parses the complete head in h[0..n) (ending in CRLF CRLF). */
static bst_h1_result parse(bst_h1_resp_parser *p, const char *h, size_t n, bst_h1_resp_head *out)
{
	/* "HTTP/1.x SSS" */
	if (n < 14 || memcmp(h, "HTTP/1.", 7) != 0 || (h[7] != '0' && h[7] != '1') || h[8] != ' ')
		return err502();
	for (int i = 9; i < 12; i++)
		if (h[i] < '0' || h[i] > '9')
			return err502();
	int status = (h[9] - '0') * 100 + (h[10] - '0') * 10 + (h[11] - '0');
	if (status < 100 || status > 599)
		return err502();
	size_t i = 12, rs = 12, re;
	if (h[i] == ' ')
		rs = ++i;
	else if (h[i] != '\r')
		return err502();
	while (i < n && h[i] != '\r') {
		if (!is_vchar_or_ws((unsigned char)h[i]))
			return err502(); /* a bare LF or control byte in the reason */
		i++;
	}
	re = i;
	if (i + 1 >= n || h[i + 1] != '\n')
		return err502();
	i += 2;
	char *copy = bst_arena_alloc(p->arena, n);
	if (copy == NULL)
		return err502();
	memcpy(copy, h, n);
	out->status = status;
	out->version_minor = (uint8_t)(h[7] - '0');
	out->reason = (bst_str){ copy + rs, (uint32_t)(re - rs) };
	bst_headers_init(&out->headers, p->arena);
	/* fields until the empty line */
	while (!(h[i] == '\r' && i + 1 < n && h[i + 1] == '\n')) {
		size_t ns = i;
		while (i < n && bst_is_tchar((unsigned char)h[i]))
			i++;
		if (i == ns || i >= n || h[i] != ':') /* no name, a space before ':', obs-fold */
			return err502();
		size_t ne = i++;
		while (i < n && (h[i] == ' ' || h[i] == '\t'))
			i++;
		size_t vs = i;
		while (i < n && h[i] != '\r') {
			if (!is_vchar_or_ws((unsigned char)h[i]))
				return err502();
			i++;
		}
		if (i + 1 >= n || h[i + 1] != '\n')
			return err502();
		size_t ve = i;
		while (ve > vs && (h[ve - 1] == ' ' || h[ve - 1] == '\t'))
			ve--;
		i += 2;
		if (bst_headers_add(&out->headers, (bst_str){ copy + ns, (uint32_t)(ne - ns) },
				    (bst_str){ copy + vs, (uint32_t)(ve - vs) }) != 0)
			return err502();
	}
	return (bst_h1_result){ .kind = BST_H1_DONE, .consumed = i + 2 };
}

bst_h1_result bst_h1_parse_resp_head(bst_h1_resp_parser *p, const char *buf, size_t len,
				     size_t max_head, bst_h1_resp_head *out)
{
	size_t lim = len < max_head ? len : max_head;
	size_t i = p->scanned >= 3 ? p->scanned - 3 : 0;
	for (; i + 3 < lim; i++) {
		if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
			return parse(p, buf, i + 4, out);
		if (buf[i] == '\n' && (i == 0 || buf[i - 1] != '\r'))
			return err502(); /* a bare LF: never a line end from an upstream */
	}
	p->scanned = i > 0 ? i : 0;
	if (len >= max_head)
		return err502(); /* the head does not fit */
	return (bst_h1_result){ .kind = BST_H1_NEED_MORE };
}

static bst_str trim(bst_str s)
{
	while (s.len > 0 && (s.p[0] == ' ' || s.p[0] == '\t')) {
		s.p++;
		s.len--;
	}
	while (s.len > 0 && (s.p[s.len - 1] == ' ' || s.p[s.len - 1] == '\t'))
		s.len--;
	return s;
}

/* Calls fn for each element of a comma list; stops early when fn returns false. */
static bool each_elem(bst_str v, bool (*fn)(bst_str, void *), void *ud)
{
	size_t st = 0;
	for (size_t i = 0; i <= v.len; i++) {
		if (i == v.len || v.p[i] == ',') {
			bst_str e = trim((bst_str){ v.p + st, (uint32_t)(i - st) });
			if (e.len > 0 && !fn(e, ud))
				return false;
			st = i + 1;
		}
	}
	return true;
}

static bool match_name(bst_str e, void *ud)
{
	return !bst_str_ieq(e, *(bst_str *)ud);
}

bool bst_h1_connection_lists(const bst_headers *h, bst_str name)
{
	for (const bst_header *c = bst_headers_next(h, NULL, BST_H_CONNECTION); c != NULL;
	     c = bst_headers_next(h, c, BST_H_CONNECTION))
		if (!each_elem(c->value, match_name, &name))
			return true;
	return false;
}

typedef struct te_scan {
	unsigned codings;
	bool chunked_last, chunked_seen, bad;
} te_scan;

static bool te_elem(bst_str e, void *ud)
{
	te_scan *t = ud;
	/* parameters (`;q=`) are not used on Transfer-Encoding; keep the coding name */
	const char *semi = memchr(e.p, ';', e.len);
	if (semi != NULL)
		e = trim((bst_str){ e.p, (uint32_t)(semi - e.p) });
	bool ch = bst_str_ieq(e, BST_S("chunked"));
	if (ch && t->chunked_seen)
		t->bad = true;
	t->chunked_seen = t->chunked_seen || ch;
	t->chunked_last = ch;
	t->codings++;
	return true;
}

int bst_h1_resp_framing_of(const bst_h1_resp_head *h, bool head_request, bst_h1_resp_framing *out)
{
	memset(out, 0, sizeof *out);
	const bst_headers *hs = &h->headers;
	bool has_te = bst_headers_get(hs, BST_H_TRANSFER_ENCODING) != NULL;
	const bst_header *cl = bst_headers_get(hs, BST_H_CONTENT_LENGTH);
	if (has_te && cl != NULL)
		return -1; /* request smuggling's favourite shape: never forwarded */
	if (has_te && h->version_minor == 0)
		return -1;
	out->keepalive = h->version_minor >= 1 && !bst_h1_connection_lists(hs, BST_S("close"));
	if (head_request || (h->status >= 100 && h->status < 200) || h->status == 204 ||
	    h->status == 304) {
		out->kind = BST_RESP_BODY_NONE;
		return 0;
	}
	if (has_te) {
		te_scan t = { 0 };
		for (const bst_header *x = bst_headers_next(hs, NULL, BST_H_TRANSFER_ENCODING); x != NULL;
		     x = bst_headers_next(hs, x, BST_H_TRANSFER_ENCODING))
			each_elem(x->value, te_elem, &t);
		if (t.bad || t.codings == 0 || (t.chunked_seen && !t.chunked_last))
			return -1;
		if (t.chunked_last) {
			out->kind = BST_RESP_BODY_CHUNKED;
		} else {
			out->kind = BST_RESP_BODY_CLOSE;
			out->keepalive = false;
		}
		return 0;
	}
	if (cl != NULL) {
		bool have = false;
		uint64_t len = 0;
		for (const bst_header *x = cl; x != NULL; x = bst_headers_next(hs, x, BST_H_CONTENT_LENGTH)) {
			/* a list of identical values ("5, 5") is one value (RFC 9110 section 8.6) */
			size_t st = 0;
			bst_str v = x->value;
			for (size_t i = 0; i <= v.len; i++) {
				if (i < v.len && v.p[i] != ',')
					continue;
				bst_str e = trim((bst_str){ v.p + st, (uint32_t)(i - st) });
				uint64_t n;
				bool digits = e.len > 0 && e.len <= 19;
				for (size_t k = 0; digits && k < e.len; k++)
					digits = e.p[k] >= '0' && e.p[k] <= '9';
				if (!digits || !bst_str_to_u64(e, &n) || (have && n != len))
					return -1;
				len = n;
				have = true;
				st = i + 1;
			}
		}
		out->kind = BST_RESP_BODY_LENGTH;
		out->length = len;
		return 0;
	}
	out->kind = BST_RESP_BODY_CLOSE;
	out->keepalive = false;
	return 0;
}

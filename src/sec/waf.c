/* See waf.h. */
#include "sec/waf.h"

#include "core/arena.h"
#include "core/err.h"
#include "sec/acl.h"
#include "tls/conn.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const bst_stream_ops bst_h2_ops, bst_h3_ops;

static const char *const subject_names[BST_WAF_SUBJECTS] = {
	"path", "uri", "query", "arg:", "header:", "cookie:", "method", "host", "ip", "ja4",
	"content_type", "content_length", "user_agent", "protocol", "tls_version",
};
static const char *const op_names[BST_WAF_OPS] = {
	"=", "!=", "~", "!~", "prefix", "suffix", "contains", "in_cidr", "in_file", ">", "<", "missing", "exists",
};

/* ---- parsing ---- */

static int fail(char *why, size_t cap, const char *msg)
{
	snprintf(why, cap, "%s", msg);
	return -1;
}

static int cmp_str(const void *a, const void *b)
{
	const bst_str *x = a, *y = b;
	uint32_t n = x->len < y->len ? x->len : y->len;
	int c = memcmp(x->p, y->p, n);
	return c != 0 ? c : (x->len > y->len) - (x->len < y->len);
}

/* A file of exact values, one per line ('#' comments), sorted for bsearch. */
static int load_words(bst_waf_match *m, const char *path, char *why, size_t cap)
{
	FILE *f = fopen(path, "re");
	if (f == NULL) {
		snprintf(why, cap, "can not open '%s': %s", path, strerror(errno));
		return -1;
	}
	bst_str *v = NULL;
	size_t n = 0, vc = 0;
	char *line = NULL;
	size_t lcap = 0;
	ssize_t len;
	int rc = 0;
	while ((len = getline(&line, &lcap, f)) >= 0) {
		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' || line[len - 1] == ' '))
			len--;
		if (len == 0 || line[0] == '#')
			continue;
		if (n == vc) {
			size_t nc = vc ? vc * 2 : 64;
			bst_str *nv = realloc(v, nc * sizeof *nv);
			if (nv == NULL) {
				rc = fail(why, cap, "out of memory");
				break;
			}
			v = nv;
			vc = nc;
		}
		char *p = malloc((size_t)len);
		if (p == NULL) {
			rc = fail(why, cap, "out of memory");
			break;
		}
		memcpy(p, line, (size_t)len);
		v[n++] = (bst_str){ p, (uint32_t)len };
	}
	free(line);
	fclose(f);
	if (rc != 0) {
		for (size_t i = 0; i < n; i++)
			free((void *)v[i].p);
		free(v);
		return -1;
	}
	if (n > 0)
		qsort(v, n, sizeof *v, cmp_str);
	m->words = v;
	m->nwords = n;
	return 0;
}

int bst_waf_match_parse(bst_waf_match *m, bst_str subject, bst_str op, const bst_str *value,
			bst_arena *a, char *why, size_t cap)
{
	memset(m, 0, sizeof *m);
	int si = -1, oi = -1;
	for (int i = 0; i < BST_WAF_SUBJECTS; i++) {
		size_t n = strlen(subject_names[i]);
		bool prefixed = subject_names[i][n - 1] == ':';
		if (prefixed ? subject.len > n && memcmp(subject.p, subject_names[i], n) == 0
			     : bst_str_eq(subject, (bst_str){ subject_names[i], (uint32_t)n })) {
			si = i;
			if (prefixed)
				m->name = (bst_str){ subject.p + n, (uint32_t)(subject.len - n) };
			break;
		}
	}
	if (si < 0)
		return fail(why, cap, "unknown subject (path, uri, query, arg:NAME, header:NAME, cookie:NAME, "
				      "method, host, ip, ja4, content_type, content_length, user_agent, "
				      "protocol, tls_version)");
	for (int i = 0; i < BST_WAF_OPS; i++)
		if (bst_str_eq(op, (bst_str){ op_names[i], (uint32_t)strlen(op_names[i]) }))
			oi = i;
	if (oi < 0)
		return fail(why, cap, "unknown operator (= != ~ !~ prefix suffix contains in_cidr in_file > < "
				      "missing exists)");
	m->subject = (uint8_t)si;
	m->op = (uint8_t)oi;
	if (m->name.len > 0) { /* the caller's text (the config AST) does not outlive the config */
		char *nm = bst_arena_alloc(a, m->name.len);
		if (nm == NULL)
			return fail(why, cap, "out of memory");
		memcpy(nm, m->name.p, m->name.len);
		m->name.p = nm;
	}
	bool unary = oi == BST_WAF_MISSING || oi == BST_WAF_EXISTS;
	if (unary != (value == NULL))
		return fail(why, cap, unary ? "missing and exists take no value" : "this operator needs a value");
	if (value != NULL) {
		char *v = bst_arena_alloc(a, (size_t)value->len + 1);
		if (v == NULL)
			return fail(why, cap, "out of memory");
		memcpy(v, value->p, value->len);
		v[value->len] = '\0';
		m->value = (bst_str){ v, value->len };
	}
	switch (oi) {
	case BST_WAF_RE:
	case BST_WAF_NRE: {
		bst_err e = { .msg = "" };
		m->re = bst_regex_compile(m->value, false, &e);
		if (m->re == NULL) {
			snprintf(why, cap, "bad regex: %s", e.msg);
			return -1;
		}
		return 0;
	}
	case BST_WAF_IN_CIDR:
		if (si != BST_WAF_IP)
			return fail(why, cap, "in_cidr applies to ip only");
		if (!bst_cidr_parse(m->value, &m->cidr)) {
			bst_ip ip;
			if (!bst_addr_parse(m->value, &ip))
				return fail(why, cap, "in_cidr needs a CIDR");
			m->cidr.ip = bst_ip_canon(&ip);
			m->cidr.prefix = m->cidr.ip.family == BST_IP_V4 ? 32 : 128;
		}
		m->cidr.ip = bst_ip_canon(&m->cidr.ip);
		return 0;
	case BST_WAF_IN_FILE:
		if (si == BST_WAF_IP) {
			size_t n = 0;
			char w[128];
			m->cidrs = bst_acl_load_file(m->value.p, &n, w, sizeof w);
			if (m->cidrs == NULL) {
				snprintf(why, cap, "can not load '%s': %s", m->value.p, w);
				return -1;
			}
			return 0;
		}
		return load_words(m, m->value.p, why, cap);
	case BST_WAF_GT:
	case BST_WAF_LT: {
		char *end;
		errno = 0;
		long long x = strtoll(m->value.p, &end, 10);
		if (errno != 0 || *end != '\0' || m->value.len == 0)
			return fail(why, cap, "> and < compare with a whole number");
		m->num = x;
		return 0;
	}
	default:
		return 0;
	}
}

void bst_waf_match_free(bst_waf_match *m)
{
	bst_regex_free(m->re);
	m->re = NULL;
	if (m->cidrs != NULL)
		bst_cidrset_free((bst_cidrset *)m->cidrs);
	m->cidrs = NULL;
	for (size_t i = 0; i < m->nwords; i++)
		free((void *)m->words[i].p);
	free((void *)m->words);
	m->words = NULL;
	m->nwords = 0;
}

/* How much a match costs: headers and lookups before files, regexes last. */
static int cost(const bst_waf_match *m)
{
	int c = m->op == BST_WAF_RE || m->op == BST_WAF_NRE ? 100 : m->op == BST_WAF_IN_FILE ? 20 : 0;
	if (m->subject == BST_WAF_ARG || m->subject == BST_WAF_COOKIE || m->subject == BST_WAF_HEADER)
		c += 5;
	return c;
}

void bst_waf_rule_order(bst_waf_rule *r)
{
	for (size_t i = 1; i < r->nm; i++) { /* stable insertion sort: rules are short */
		bst_waf_match x = r->m[i];
		size_t j = i;
		while (j > 0 && cost(&r->m[j - 1]) > cost(&x)) {
			r->m[j] = r->m[j - 1];
			j--;
		}
		r->m[j] = x;
	}
}

/* ---- the values of a subject ---- */

#define MAXV 128 /* values of one subject looked at: repeated headers, arguments, cookies */

typedef struct vals {
	bst_str v[MAXV];
	unsigned n;
	bool trunc;
} vals;

static void put(vals *o, bst_str v)
{
	if (o->n < MAXV)
		o->v[o->n++] = v;
	else
		o->trunc = true;
}

static int hexv(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/* Percent and '+' decoding of a query part, into the stream's arena (the raw text on failure). */
static bst_str qdecode(const bst_stream *s, bst_str in)
{
	if (memchr(in.p, '%', in.len) == NULL && memchr(in.p, '+', in.len) == NULL)
		return in;
	char *o = bst_arena_alloc(s->arena, in.len + 1u);
	if (o == NULL)
		return in;
	uint32_t n = 0;
	for (uint32_t i = 0; i < in.len; i++) {
		char c = in.p[i];
		if (c == '%' && i + 2 < in.len && hexv(in.p[i + 1]) >= 0 && hexv(in.p[i + 2]) >= 0) {
			o[n++] = (char)(hexv(in.p[i + 1]) * 16 + hexv(in.p[i + 2]));
			i += 2;
		} else {
			o[n++] = c == '+' ? ' ' : c;
		}
	}
	return (bst_str){ o, n };
}

static void query_args(const bst_stream *s, bst_str name, vals *o)
{
	const bst_req_head *h = &s->req.head;
	if (!h->has_query)
		return;
	const char *p = h->query.p, *end = p + h->query.len;
	while (p < end) {
		const char *amp = memchr(p, '&', (size_t)(end - p));
		const char *e = amp != NULL ? amp : end;
		const char *eq = memchr(p, '=', (size_t)(e - p));
		bst_str k = { p, (uint32_t)((eq != NULL ? eq : e) - p) };
		bst_str v = eq != NULL ? (bst_str){ eq + 1, (uint32_t)(e - eq - 1) } : (bst_str){ "", 0 };
		if (k.len > 0 && bst_str_eq(qdecode(s, k), name))
			put(o, qdecode(s, v));
		p = e + 1;
	}
}

static void cookies(const bst_stream *s, bst_str name, vals *o)
{
	const bst_header *h = NULL;
	while ((h = bst_headers_next(&s->req.head.headers, h, BST_H_COOKIE)) != NULL) {
		const char *p = h->value.p, *end = p + h->value.len;
		while (p < end) {
			while (p < end && (*p == ' ' || *p == ';' || *p == '\t'))
				p++;
			const char *semi = memchr(p, ';', (size_t)(end - p));
			const char *e = semi != NULL ? semi : end;
			const char *eq = memchr(p, '=', (size_t)(e - p));
			if (eq != NULL && bst_str_eq((bst_str){ p, (uint32_t)(eq - p) }, name)) {
				const char *ve = e;
				while (ve > eq + 1 && (ve[-1] == ' ' || ve[-1] == '\t'))
					ve--;
				put(o, (bst_str){ eq + 1, (uint32_t)(ve - eq - 1) });
			}
			p = e;
		}
	}
}

static void header_all(const bst_stream *s, bst_str name, vals *o)
{
	const bst_header *h = NULL;
	while ((h = bst_headers_next_name(&s->req.head.headers, h, name)) != NULL)
		put(o, h->value);
}

static void header_id(const bst_stream *s, bst_hdr_id id, vals *o)
{
	const bst_header *h = NULL;
	while ((h = bst_headers_next(&s->req.head.headers, h, id)) != NULL)
		put(o, h->value);
}

static bst_str cstr(const char *v)
{
	return (bst_str){ v, (uint32_t)strlen(v) };
}

static bst_str host_of(const bst_stream *s)
{
	bst_str h = s->req.head.authority;
	if (h.len == 0) {
		const bst_header *x = bst_headers_get(&s->req.head.headers, BST_H_HOST);
		if (x != NULL)
			h = x->value;
	}
	if (h.len > 0 && h.p[0] == '[') { /* [v6]:port */
		const char *rb = memchr(h.p, ']', h.len);
		return rb != NULL ? (bst_str){ h.p, (uint32_t)(rb - h.p + 1) } : h;
	}
	const char *colon = h.len > 0 ? memchr(h.p, ':', h.len) : NULL;
	return colon != NULL ? (bst_str){ h.p, (uint32_t)(colon - h.p) } : h;
}

static void values(const bst_waf_match *m, const bst_stream *s, vals *o, char *ipbuf, char *numbuf)
{
	const bst_req_head *h = &s->req.head;
	switch (m->subject) {
	case BST_WAF_PATH:
		put(o, s->uri.p != NULL ? s->uri : h->path);
		break;
	case BST_WAF_URI:
		put(o, h->target);
		break;
	case BST_WAF_QUERY:
		if (h->has_query)
			put(o, h->query);
		break;
	case BST_WAF_ARG:
		query_args(s, m->name, o);
		break;
	case BST_WAF_HEADER:
		header_all(s, m->name, o);
		break;
	case BST_WAF_COOKIE:
		cookies(s, m->name, o);
		break;
	case BST_WAF_METHOD:
		put(o, h->method_str);
		break;
	case BST_WAF_HOST: {
		bst_str x = host_of(s);
		if (x.len > 0)
			put(o, x);
		break;
	}
	case BST_WAF_IP:
		if (s->sec_ip_set && bst_addr_format(&s->sec_ip, ipbuf, BST_ADDR_STRLEN) > 0)
			put(o, cstr(ipbuf));
		break;
	case BST_WAF_JA4:
	case BST_WAF_TLS_VERSION: {
		const char *v = s->transport != NULL
			? bst_tls_var(s->transport, m->subject == BST_WAF_JA4 ? "ja4" : "protocol") : NULL;
		if (v != NULL && v[0] != '\0')
			put(o, cstr(v));
		break;
	}
	case BST_WAF_CONTENT_TYPE:
		header_id(s, BST_H_CONTENT_TYPE, o);
		break;
	case BST_WAF_CONTENT_LENGTH:
		header_id(s, BST_H_CONTENT_LENGTH, o);
		break;
	case BST_WAF_USER_AGENT:
		header_id(s, BST_H_USER_AGENT, o);
		break;
	case BST_WAF_PROTOCOL:
		if (s->ops == &bst_h3_ops)
			put(o, BST_S("HTTP/3"));
		else if (s->ops == &bst_h2_ops)
			put(o, BST_S("HTTP/2"));
		else {
			snprintf(numbuf, 16, "HTTP/1.%u", (unsigned)h->version_minor);
			put(o, cstr(numbuf));
		}
		break;
	default:
		break;
	}
}

/* ---- matching one value ---- */

static bool find(bst_str hay, bst_str needle)
{
	if (needle.len == 0)
		return true;
	if (needle.len > hay.len)
		return false;
	return memmem(hay.p, hay.len, needle.p, needle.len) != NULL;
}

static bool number(bst_str v, int64_t *out)
{
	if (v.len == 0 || v.len > 18)
		return false;
	int64_t x = 0;
	for (uint32_t i = 0; i < v.len; i++) {
		if (v.p[i] < '0' || v.p[i] > '9')
			return false;
		x = x * 10 + (v.p[i] - '0');
	}
	*out = x;
	return true;
}

/* The positive form of the operator against one value. -1: a regex hit its limit. */
static int one(const bst_waf_match *m, const bst_stream *s, bst_str v)
{
	switch (m->op) {
	case BST_WAF_EQ:
	case BST_WAF_NE:
		if (m->subject == BST_WAF_CONTENT_LENGTH) {
			int64_t a, b;
			return number(v, &a) && number(m->value, &b) && a == b;
		}
		return bst_str_eq(v, m->value);
	case BST_WAF_RE:
	case BST_WAF_NRE: {
		int r = bst_regex_match(m->re, v, NULL);
		return r == BST_RE_LIMIT ? -1 : r == BST_RE_MATCH;
	}
	case BST_WAF_PREFIX:
		return v.len >= m->value.len && memcmp(v.p, m->value.p, m->value.len) == 0;
	case BST_WAF_SUFFIX:
		return v.len >= m->value.len && memcmp(v.p + v.len - m->value.len, m->value.p, m->value.len) == 0;
	case BST_WAF_CONTAINS:
		return find(v, m->value);
	case BST_WAF_IN_CIDR: {
		if (!s->sec_ip_set)
			return 0;
		bst_ip ip = bst_ip_canon(&s->sec_ip);
		if (ip.family != m->cidr.ip.family)
			return 0;
		unsigned p = m->cidr.prefix;
		for (unsigned i = 0; i < 16 && p > 0; i++) {
			unsigned bits = p >= 8 ? 8 : p;
			uint8_t mask = (uint8_t)(0xff00u >> bits);
			if ((ip.b[i] & mask) != (m->cidr.ip.b[i] & mask))
				return 0;
			p -= bits;
		}
		return 1;
	}
	case BST_WAF_IN_FILE:
		if (m->cidrs != NULL) {
			if (!s->sec_ip_set)
				return 0;
			bst_ip ip = bst_ip_canon(&s->sec_ip);
			return bst_cidrset_match(m->cidrs, &ip) != NULL;
		}
		return m->nwords > 0 && bsearch(&v, m->words, m->nwords, sizeof *m->words, cmp_str) != NULL;
	case BST_WAF_GT:
	case BST_WAF_LT: {
		int64_t x;
		if (!number(v, &x))
			return 0;
		return m->op == BST_WAF_GT ? x > m->num : x < m->num;
	}
	default:
		return 0;
	}
}

bool bst_waf_match_eval(const bst_waf_match *m, const bst_stream *s, bool *limit)
{
	vals o = { .n = 0 };
	char ipbuf[BST_ADDR_STRLEN], numbuf[16];
	values(m, s, &o, ipbuf, numbuf);
	if (m->op == BST_WAF_MISSING)
		return o.n == 0;
	if (m->op == BST_WAF_EXISTS)
		return o.n > 0;
	if (o.trunc) { /* more values than are looked at: as a regex over its limit */
		*limit = true;
		return true;
	}
	bool negated = m->op == BST_WAF_NE || m->op == BST_WAF_NRE;
	for (unsigned i = 0; i < o.n; i++) {
		int r = one(m, s, o.v[i]);
		if (r < 0) {
			*limit = true;
			return true; /* the caller decides what a limit means for this rule */
		}
		if (negated ? r == 0 : r == 1)
			return true;
	}
	return false;
}

/* ---- a set of rules ---- */

bst_waf_action bst_waf_eval(const bst_cfg_list *rules, const bst_stream *s, bst_waf_on_match cb, void *ud)
{
	bst_waf_action a = { .verdict = BST_WAF_NONE };
	for (size_t i = 0; i < rules->n; i++) {
		const bst_waf_rule *r = ((const bst_waf_ref *)rules->items[i])->rule;
		if (r == NULL)
			continue;
		bool all = true;
		for (size_t j = 0; j < r->nm && all; j++) {
			bool l = false;
			all = bst_waf_match_eval(&r->m[j], s, &l);
			if (l) {
				a.regex_limit = true;
				/* fail closed only where the rule refuses: an allow must never be won by a
				 * pattern too costly to run */
				all = r->action == BST_WAF_DENY || r->action == BST_WAF_CHALLENGE;
			}
		}
		if (!all)
			continue;
		if (cb != NULL)
			cb(r, s, ud);
		if (r->action == BST_WAF_NONE) /* log: go on */
			continue;
		a.verdict = r->action;
		a.rule = r;
		a.status = r->status;
		return a;
	}
	return a;
}

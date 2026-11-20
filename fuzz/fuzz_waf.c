/* libFuzzer harness for WAF rules (sec/waf.c): parsing a `match <subject> <op> [value]` line as the
 * config loader hands it over (PCRE2 compilation for ~ and !~, CIDRs for in_cidr), then evaluating
 * it against a fuzzed request, which drives the WAF's own parsing of client input: query
 * arguments with percent-decoding, the Cookie header, repeated headers, Content-Length.
 *
 * Input: subject, op and value on the first three lines; every later line is the request: first
 * the target ("/path?query"), then "Name: value" headers. A value with no third line is NULL (as
 * for `missing`). in_file is skipped: it opens a file named by the value.
 * Properties: no crash or leak; an accepted match has a subject and op inside their enums and a
 * regex exactly when the op is ~ or !~; evaluating it twice gives the same answer. */
#include "core/addr.h"
#include "core/arena.h"
#include "route/uri.h"
#include "sec/waf.h"

#include <stdlib.h>
#include <string.h>

static bst_str line(const char **p, const char *end, bool *found)
{
	const char *s = *p, *nl = memchr(s, '\n', (size_t)(end - s));
	*found = nl != NULL;
	*p = nl != NULL ? nl + 1 : end;
	return (bst_str){ s, (uint32_t)((nl != NULL ? nl : end) - s) };
}

static void eval(const bst_waf_match *m, const char *p, const char *end, bst_arena *a)
{
	bst_stream s;
	bst_cfg_common cfg;
	memset(&s, 0, sizeof s);
	memset(&cfg, 0, sizeof cfg);
	s.arena = a;
	s.cfg = &cfg;
	bst_req_head *h = &s.req.head;
	h->method_str = BST_S("GET");
	h->version_minor = 1;
	bool more;
	bst_str target = line(&p, end, &more);
	if (target.len == 0)
		target = BST_S("/");
	h->target = target;
	const char *q = memchr(target.p, '?', target.len);
	h->path = q != NULL ? (bst_str){ target.p, (uint32_t)(q - target.p) } : target;
	if (q != NULL) {
		h->has_query = true;
		h->query = (bst_str){ q + 1, (uint32_t)(target.p + target.len - q - 1) };
	}
	static char uri[4096 + 1];
	size_t n = 0;
	if (bst_uri_normalize(h->path, uri, sizeof uri, 0, &n) == BST_URI_OK)
		s.uri = (bst_str){ uri, (uint32_t)n };
	bst_headers_init(&h->headers, a);
	while (more && p < end) {
		bst_str ln = line(&p, end, &more);
		const char *c = memchr(ln.p, ':', ln.len);
		if (c == NULL || c == ln.p)
			continue;
		const char *v = c + 1;
		while (v < ln.p + ln.len && *v == ' ')
			v++;
		(void)bst_headers_add(&h->headers, (bst_str){ ln.p, (uint32_t)(c - ln.p) },
				      (bst_str){ v, (uint32_t)(ln.p + ln.len - v) });
	}
	bst_ip ip;
	if (bst_addr_parse(BST_S("192.0.2.10"), &ip)) {
		s.sec_ip = ip;
		s.sec_ip_set = true;
	}
	bool l1 = false, l2 = false;
	bool r1 = bst_waf_match_eval(m, &s, &l1);
	bool r2 = bst_waf_match_eval(m, &s, &l2);
	if (r1 != r2 || l1 != l2)
		abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size > 4096)
		return 0;
	char *buf = malloc(size > 0 ? size : 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, d, size);
	const char *p = buf, *end = buf + size;
	bool has_op = false, has_val = false, more = false;
	bst_str subject = line(&p, end, &has_op);
	bst_str op = has_op ? line(&p, end, &has_val) : (bst_str){ NULL, 0 };
	bst_str value = has_op && has_val ? line(&p, end, &more) : (bst_str){ NULL, 0 };
	bool have_value = has_op && has_val;
	if (!has_op || bst_str_eq(op, BST_S("in_file"))) {
		free(buf);
		return 0;
	}
	bst_arena *a = bst_arena_new(4096);
	if (a == NULL) {
		free(buf);
		return 0;
	}
	bst_waf_match m;
	memset(&m, 0, sizeof m);
	char why[256];
	why[0] = '\0';
	if (bst_waf_match_parse(&m, subject, op, have_value ? &value : NULL, a, why, sizeof why) == 0) {
		if (m.subject >= BST_WAF_SUBJECTS || m.op >= BST_WAF_OPS)
			abort();
		bool re = m.op == BST_WAF_RE || m.op == BST_WAF_NRE;
		if (re != (m.re != NULL))
			abort();
		if (have_value && more)
			eval(&m, p, end, a);
		bst_waf_match_free(&m);
	} else if (memchr(why, '\0', sizeof why) == NULL) {
		abort();
	}
	bst_arena_free(a);
	free(buf);
	return 0;
}

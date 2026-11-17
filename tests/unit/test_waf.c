/* WAF-lite (sec/waf.h): every subject and operator, matching after path normalization, repeated
 * and missing headers, rule order, regex limits and the cost of a thousand rules. */
#include "core/arena.h"
#include "route/uri.h"
#include "sec/waf.h"
#include "tap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct fx {
	bst_stream s;
	bst_cfg_common cfg;
	bst_arena *a;
	char uri[256];
} fx;

static bst_str S_(const char *s)
{
	return (bst_str){ s, (uint32_t)strlen(s) };
}

/* A request: "METHOD /raw/path?query", headers as "Name: value" lines. */
static void fx_init(fx *f, const char *method, const char *target, const char *const *hdrs)
{
	memset(f, 0, sizeof *f);
	f->a = bst_arena_new(4096);
	f->s.arena = f->a;
	f->s.cfg = &f->cfg;
	bst_req_head *h = &f->s.req.head;
	h->method_str = S_(method);
	h->target = S_(target);
	h->version_minor = 1;
	const char *q = strchr(target, '?');
	h->path = q != NULL ? (bst_str){ target, (uint32_t)(q - target) } : S_(target);
	if (q != NULL) {
		h->has_query = true;
		h->query = S_(q + 1);
	}
	size_t n = 0;
	if (bst_uri_normalize(h->path, f->uri, sizeof f->uri, 0, &n) == BST_URI_OK)
		f->s.uri = (bst_str){ f->uri, (uint32_t)n };
	bst_headers_init(&h->headers, f->a);
	for (size_t i = 0; hdrs != NULL && hdrs[i] != NULL; i++) {
		const char *c = strchr(hdrs[i], ':');
		(void)bst_headers_add(&h->headers, (bst_str){ hdrs[i], (uint32_t)(c - hdrs[i]) }, S_(c + 2));
	}
	bst_ip ip;
	if (bst_addr_parse(BST_S("192.0.2.10"), &ip)) {
		f->s.sec_ip = ip;
		f->s.sec_ip_set = true;
	}
}

static void fx_free(fx *f)
{
	bst_arena_free(f->a);
}

static bst_arena *g_cfg;

/* Parses and evaluates one match line; -1 when it does not parse. */
static int m1(fx *f, const char *subject, const char *op, const char *value)
{
	bst_waf_match m;
	char why[256];
	bst_str v = value != NULL ? S_(value) : (bst_str){ NULL, 0 };
	if (bst_waf_match_parse(&m, S_(subject), S_(op), value != NULL ? &v : NULL, g_cfg, why, sizeof why) != 0)
		return -1;
	bool limit = false;
	int r = bst_waf_match_eval(&m, &f->s, &limit) ? 1 : 0;
	bst_waf_match_free(&m);
	return limit ? 2 : r;
}

static const char *const HDRS[] = {
	"Host: example.com:8443", "User-Agent: curl/8.5.0", "Content-Type: application/json",
	"Content-Length: 1234", "Cookie: sid=abc; theme=dark", "X-Api-Key: k1", NULL,
};

TEST(each_subject)
{
	g_cfg = bst_arena_new(4096);
	fx f;
	fx_init(&f, "POST", "/api/v1/items?id=42&q=a%20b", HDRS);
	static const struct { const char *subj, *op, *val; int want; } t[] = {
		{ "path", "=", "/api/v1/items", 1 },
		{ "uri", "=", "/api/v1/items?id=42&q=a%20b", 1 },
		{ "query", "contains", "id=42", 1 },
		{ "arg:id", "=", "42", 1 },
		{ "arg:q", "=", "a b", 1 }, /* decoded */
		{ "arg:nope", "exists", NULL, 0 },
		{ "header:x-api-key", "=", "k1", 1 }, /* header names ignore case */
		{ "cookie:theme", "=", "dark", 1 },
		{ "cookie:sid", "=", "abc", 1 },
		{ "method", "=", "POST", 1 },
		{ "host", "=", "example.com", 1 }, /* without the port */
		{ "ip", "=", "192.0.2.10", 1 },
		{ "ip", "in_cidr", "192.0.2.0/24", 1 },
		{ "ja4", "missing", NULL, 1 }, /* cleartext */
		{ "content_type", "prefix", "application/", 1 },
		{ "content_length", ">", "1000", 1 },
		{ "user_agent", "~", "^curl/", 1 },
		{ "protocol", "=", "HTTP/1.1", 1 },
		{ "tls_version", "missing", NULL, 1 },
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
		int got = m1(&f, t[i].subj, t[i].op, t[i].val);
		if (got != t[i].want)
			printf("# %s %s %s: got %d\n", t[i].subj, t[i].op, t[i].val ? t[i].val : "", got);
		ASSERT_EQ(got, t[i].want);
	}
	ASSERT_EQ(m1(&f, "bogus", "=", "x"), -1);
	ASSERT_EQ(m1(&f, "path", "=~", "x"), -1);
	ASSERT_EQ(m1(&f, "path", "=", NULL), -1);	  /* a value is needed */
	ASSERT_EQ(m1(&f, "path", "exists", "x"), -1);	  /* and refused */
	ASSERT_EQ(m1(&f, "path", "~", "(unclosed"), -1); /* a bad regex */
	ASSERT_EQ(m1(&f, "path", "in_cidr", "10.0.0.0/8"), -1);
	fx_free(&f);
}

TEST(each_op)
{
	fx f;
	fx_init(&f, "GET", "/shop/cart.php?n=7", HDRS);
	char path[] = "/tmp/bst_waf_words_XXXXXX";
	int fd = mkstemp(path);
	ASSERT(fd >= 0);
	const char words[] = "# bad agents\nsqlmap/1.0\ncurl/8.5.0\nnikto\n";
	ASSERT_EQ(write(fd, words, sizeof words - 1), (long)(sizeof words - 1));
	close(fd);
	const struct { const char *subj, *op, *val; int want; } t[] = {
		{ "path", "=", "/shop/cart.php", 1 }, { "path", "=", "/shop", 0 },
		{ "path", "!=", "/shop", 1 },	       { "path", "!=", "/shop/cart.php", 0 },
		{ "path", "~", "\\.php$", 1 },	       { "path", "~", "\\.asp$", 0 },
		{ "path", "!~", "\\.asp$", 1 },	       { "path", "!~", "\\.php$", 0 },
		{ "path", "prefix", "/shop/", 1 },     { "path", "prefix", "/admin", 0 },
		{ "path", "suffix", ".php", 1 },       { "path", "suffix", ".html", 0 },
		{ "path", "contains", "cart", 1 },     { "path", "contains", "basket", 0 },
		{ "ip", "in_cidr", "192.0.2.0/28", 1 }, { "ip", "in_cidr", "198.51.100.0/24", 0 },
		{ "arg:n", ">", "6", 1 },	       { "arg:n", ">", "7", 0 },
		{ "arg:n", "<", "8", 1 },	       { "arg:n", "<", "7", 0 },
		{ "header:x-api-key", "exists", NULL, 1 }, { "header:x-other", "exists", NULL, 0 },
		{ "header:x-other", "missing", NULL, 1 },  { "header:x-api-key", "missing", NULL, 0 },
		{ "user_agent", "in_file", path, 1 },  { "method", "in_file", path, 0 },
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
		int got = m1(&f, t[i].subj, t[i].op, t[i].val);
		if (got != t[i].want)
			printf("# %s %s %s: got %d\n", t[i].subj, t[i].op, t[i].val ? t[i].val : "", got);
		ASSERT_EQ(got, t[i].want);
	}
	unlink(path);
	fx_free(&f);
}

TEST(normalized_path)
{
	fx f;
	fx_init(&f, "GET", "/%77p-admin/./x/../install.php", NULL);
	ASSERT_EQ(m1(&f, "path", "prefix", "/wp-admin"), 1);
	ASSERT_EQ(m1(&f, "path", "=", "/wp-admin/install.php"), 1);
	ASSERT_EQ(m1(&f, "uri", "prefix", "/wp-admin"), 0); /* uri is the target as sent */
	fx_free(&f);
}

TEST(multi_header)
{
	static const char *const h[] = { "X-Forwarded-Host: good.example", "X-Forwarded-Host: evil.example",
					 "X-Forwarded-Host: good.example", NULL };
	fx f;
	fx_init(&f, "GET", "/", h);
	ASSERT_EQ(m1(&f, "header:x-forwarded-host", "=", "evil.example"), 1); /* any value */
	ASSERT_EQ(m1(&f, "header:x-forwarded-host", "!=", "good.example"), 1); /* one is not */
	ASSERT_EQ(m1(&f, "header:x-forwarded-host", "~", "^evil"), 1);
	fx_free(&f);
	/* more values than are looked at: as a regex over its limit (fail closed) */
	static const char *many[200];
	for (int i = 0; i < 199; i++)
		many[i] = "X-Dup: a";
	many[199] = NULL;
	fx_init(&f, "GET", "/", many);
	ASSERT_EQ(m1(&f, "header:x-dup", "=", "b"), 2);
	fx_free(&f);
}

TEST(missing_header)
{
	fx f;
	fx_init(&f, "GET", "/", NULL);
	ASSERT_EQ(m1(&f, "header:referer", "missing", NULL), 1);
	ASSERT_EQ(m1(&f, "header:referer", "~", ".*"), 0);
	ASSERT_EQ(m1(&f, "header:referer", "!~", "x"), 0);
	ASSERT_EQ(m1(&f, "header:referer", "!=", "x"), 0);
	ASSERT_EQ(m1(&f, "cookie:sid", "missing", NULL), 1);
	fx_free(&f);
}

/* A rule from text lines "subject op value" (value may be absent). */
static bst_waf_rule *rule(const char *name, bst_waf_verdict action, unsigned status, const char *const *lines)
{
	bst_waf_rule *r = calloc(1, sizeof *r);
	r->name = name;
	r->action = action;
	r->action_set = true;
	r->status = status;
	size_t n = 0;
	while (lines[n] != NULL)
		n++;
	r->m = calloc(n, sizeof *r->m);
	for (size_t i = 0; i < n; i++) {
		char buf[256], why[256];
		snprintf(buf, sizeof buf, "%s", lines[i]);
		char *subj = strtok(buf, " "), *op = strtok(NULL, " "), *val = strtok(NULL, "");
		bst_str v = val != NULL ? S_(val) : (bst_str){ NULL, 0 };
		if (bst_waf_match_parse(&r->m[i], S_(subj), S_(op), val != NULL ? &v : NULL, g_cfg, why, sizeof why) != 0) {
			printf("# %s: %s\n", lines[i], why);
			abort();
		}
	}
	r->nm = n;
	bst_waf_rule_order(r);
	return r;
}

static void rule_free(bst_waf_rule *r)
{
	for (size_t i = 0; i < r->nm; i++)
		bst_waf_match_free(&r->m[i]);
	free(r->m);
	free(r);
}

typedef struct rules {
	bst_cfg_list l;
	bst_waf_ref refs[1100];
	const void *items[1100];
} rules;

static void rules_set(rules *rs, bst_waf_rule *const *r, size_t n)
{
	memset(rs, 0, sizeof *rs);
	for (size_t i = 0; i < n; i++) {
		rs->refs[i].rule = r[i];
		rs->items[i] = &rs->refs[i];
	}
	rs->l.items = (const void **)rs->items;
	rs->l.n = n;
}

static void count_cb(const bst_waf_rule *r, const bst_stream *s, void *ud)
{
	(void)r, (void)s;
	(*(int *)ud)++;
}

TEST(first_match_wins)
{
	static const char *const admin[] = { "path prefix /admin", NULL };
	static const char *const office[] = { "ip in_cidr 192.0.2.0/24", "path prefix /admin", NULL };
	static const char *const any[] = { "method exists", NULL };
	bst_waf_rule *log = rule("log_admin", BST_WAF_NONE, 0, admin);
	bst_waf_rule *allow = rule("office", BST_WAF_ALLOW, 0, office);
	bst_waf_rule *deny = rule("no_admin", BST_WAF_DENY, 451, admin);
	bst_waf_rule *catchall = rule("all", BST_WAF_DENY, 403, any);
	fx f;
	fx_init(&f, "GET", "/admin/users", NULL);
	rules rs;
	int seen = 0;
	/* log goes on; the allow before the deny wins and skips the rest */
	rules_set(&rs, (bst_waf_rule *[]){ log, allow, deny, catchall }, 4);
	bst_waf_action a = bst_waf_eval(&rs.l, &f.s, count_cb, &seen);
	ASSERT_EQ(a.verdict, BST_WAF_ALLOW);
	ASSERT(a.rule == allow);
	ASSERT_EQ(seen, 2);
	/* in the other order the deny wins, with its status */
	rules_set(&rs, (bst_waf_rule *[]){ deny, allow, catchall }, 3);
	a = bst_waf_eval(&rs.l, &f.s, NULL, NULL);
	ASSERT_EQ(a.verdict, BST_WAF_DENY);
	ASSERT_EQ(a.status, 451);
	/* AND: a different client is not in the office rule */
	f.s.sec_ip.b[2] = 99;
	rules_set(&rs, (bst_waf_rule *[]){ allow, deny }, 2);
	a = bst_waf_eval(&rs.l, &f.s, NULL, NULL);
	ASSERT_EQ(a.verdict, BST_WAF_DENY);
	/* nothing matches */
	fx_free(&f);
	fx_init(&f, "GET", "/public", NULL);
	rules_set(&rs, (bst_waf_rule *[]){ deny }, 1);
	a = bst_waf_eval(&rs.l, &f.s, NULL, NULL);
	ASSERT_EQ(a.verdict, BST_WAF_NONE);
	fx_free(&f);
	rule_free(log), rule_free(allow), rule_free(deny), rule_free(catchall);
}

TEST(redos)
{
	bst_regex_set_limits(10000, 1000);
	static const char *const evil[] = { "header:x-q ~ ^(a+)+$", NULL };
	bst_waf_rule *deny = rule("redos_deny", BST_WAF_DENY, 403, evil);
	bst_waf_rule *allow = rule("redos_allow", BST_WAF_ALLOW, 0, evil);
	char v[96];
	memset(v, 'a', 64);
	strcpy(v + 64, "!");
	char hdr[128];
	snprintf(hdr, sizeof hdr, "X-Q: %s", v);
	const char *h[] = { hdr, NULL };
	fx f;
	fx_init(&f, "GET", "/", h);
	rules rs;
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	rules_set(&rs, (bst_waf_rule *[]){ deny }, 1);
	bst_waf_action a = bst_waf_eval(&rs.l, &f.s, NULL, NULL);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	ASSERT(a.regex_limit);
	ASSERT_EQ(a.verdict, BST_WAF_DENY); /* fail closed */
	ASSERT((t1.tv_sec - t0.tv_sec) < 2); /* the limit ended it, not the exponent */
	rules_set(&rs, (bst_waf_rule *[]){ allow }, 1);
	a = bst_waf_eval(&rs.l, &f.s, NULL, NULL);
	ASSERT_EQ(a.verdict, BST_WAF_NONE); /* never an allow won by a costly pattern */
	fx_free(&f);
	rule_free(deny), rule_free(allow);
	bst_regex_set_limits(0, 0);
}

TEST(evaluation_cost)
{
	enum { N = 1000 };
	static bst_waf_rule *r[N];
	char p[N][48];
	for (int i = 0; i < N; i++) {
		snprintf(p[i], sizeof p[i], "path prefix /blocked/%d", i);
		const char *lines[] = { p[i], "header:x-api-key exists", NULL };
		r[i] = rule("cost", BST_WAF_DENY, 403, lines);
	}
	static rules rs;
	rules_set(&rs, r, N);
	fx f;
	fx_init(&f, "GET", "/api/v1/items?id=1", HDRS);
	enum { ROUNDS = 200 };
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (int k = 0; k < ROUNDS; k++)
		ASSERT_EQ(bst_waf_eval(&rs.l, &f.s, NULL, NULL).verdict, BST_WAF_NONE);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	double us = ((double)(t1.tv_sec - t0.tv_sec) * 1e6 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e3) / (double)(int)ROUNDS;
	printf("# 1000 rules: %.1f us per request (this build)\n", us);
	/* the 100 us target is for an optimized build on the benchmark host (docs/tuning.md); a
	 * sanitizer build is several times slower, so this guards only against a gross regression */
	ASSERT(us < 2000.0);
	fx_free(&f);
	for (int i = 0; i < N; i++)
		rule_free(r[i]);
	bst_arena_free(g_cfg);
}

TAP_MAIN()

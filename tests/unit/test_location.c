#include "config/compile.h"
#include "config/parser.h"
#include "core/arena.h"
#include "route/location.h"
#include "route/regex.h"
#include "tap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static bst_err E;
static bst_arena *LAST;

/* One server (listening on 80) holding `body`; the registry schema, so the real post hooks run. */
static bst_config *comp(const char *body)
{
	char text[8192];
	snprintf(text, sizeof text, "server { listen 80; %s }", body);
	bst_arena_free(LAST);
	LAST = bst_arena_new(1 << 16);
	memset(&E, 0, sizeof E);
	bst_ast *ast = bst_cfg_parse_string(text, strlen(text), "t.conf", NULL, LAST, &E);
	return ast ? bst_cfg_compile(ast, &E) : NULL;
}

/* The pattern of the location chosen for uri, "-" for none, "LIMIT" for a regex that gave up. */
static const char *pick(const bst_config *cfg, const char *uri, bst_captures *caps)
{
	static bst_captures local;
	if (caps == NULL)
		caps = &local;
	const bst_cfg_location *l =
		bst_location_find(cfg->global.servers[0], (bst_str){ uri, (uint32_t)strlen(uri) }, caps);
	if (caps->limit_hit)
		return "LIMIT";
	return l ? l->pattern : "-";
}

#define CFG(var, body)                                                                  \
	bst_config *var = comp(body);                                                   \
	if (var == NULL)                                                                \
		TAP_FAIL_("compile failed: %s", E.msg)

TEST(exact_first)
{
	CFG(c, "location /a { } location = /a { } location ~ ^/a$ { }");
	ASSERT_STR(pick(c, "/a", NULL), "/a");
	const bst_cfg_location *l = bst_location_find(c->global.servers[0], BST_S("/a"), &(bst_captures){ 0 });
	ASSERT(l != NULL && l->mod == BST_LOC_EXACT); /* the exact one wins over the prefix and the regex */
	l = bst_location_find(c->global.servers[0], BST_S("/ab"), &(bst_captures){ 0 });
	ASSERT(l != NULL && l->mod == BST_LOC_PREFIX);
	bst_config_free(c);
}

TEST(exact_is_whole_uri)
{
	CFG(c, "location = /a { } location = /abc { } location = /abd { } location /ab { }");
	ASSERT_STR(pick(c, "/a", NULL), "/a");
	ASSERT_STR(pick(c, "/abc", NULL), "/abc");
	ASSERT_STR(pick(c, "/abd", NULL), "/abd");
	ASSERT_STR(pick(c, "/ab", NULL), "/ab"); /* a split node of the exact trie is not an exact hit */
	ASSERT_STR(pick(c, "/abcd", NULL), "/ab"); /* falls to the prefix */
	ASSERT_STR(pick(c, "/b", NULL), "-");
	bst_config_free(c);
}

TEST(longest_prefix)
{
	CFG(c, "location / { } location /a { } location /a/b { } location /ab { } location /a/b/c { }");
	ASSERT_STR(pick(c, "/", NULL), "/");
	ASSERT_STR(pick(c, "/x", NULL), "/");
	ASSERT_STR(pick(c, "/a", NULL), "/a");
	ASSERT_STR(pick(c, "/a/", NULL), "/a");
	ASSERT_STR(pick(c, "/a/b", NULL), "/a/b");
	ASSERT_STR(pick(c, "/a/b/c/d", NULL), "/a/b/c");
	ASSERT_STR(pick(c, "/a/bc", NULL), "/a/b");
	ASSERT_STR(pick(c, "/abc", NULL), "/ab");
	ASSERT_STR(pick(c, "/A", NULL), "/"); /* prefixes are case-sensitive */
	bst_config_free(c);
}

TEST(caret_tilde_stops_regex)
{
	CFG(c, "location ^~ /static/ { } location ~ \\.png$ { } location / { }");
	ASSERT_STR(pick(c, "/static/a.png", NULL), "/static/");
	ASSERT_STR(pick(c, "/other/a.png", NULL), "\\.png$");
	bst_config_free(c);
}

TEST(regex_order_first_match)
{
	CFG(c, "location ~ ^/x/(.+)$ { } location ~ ^/x/y$ { } location ~ ^/z { }");
	ASSERT_STR(pick(c, "/x/y", NULL), "^/x/(.+)$"); /* file order, not specificity */
	ASSERT_STR(pick(c, "/zzz", NULL), "^/z");
	ASSERT_STR(pick(c, "/q", NULL), "-");
	bst_config_free(c);
}

TEST(regex_beats_prefix)
{
	CFG(c, "location /docs/ { } location ~ ^/docs/.*\\.pdf$ { } location ~ ^/never { }");
	ASSERT_STR(pick(c, "/docs/a.pdf", NULL), "^/docs/.*\\.pdf$");
	ASSERT_STR(pick(c, "/docs/a.txt", NULL), "/docs/"); /* no regex matched: the prefix stands */
	bst_config_free(c);
}

TEST(case_insensitive)
{
	CFG(c, "location ~* \\.JPG$ { } location ~ \\.gif$ { }");
	ASSERT_STR(pick(c, "/a.jpg", NULL), "\\.JPG$");
	ASSERT_STR(pick(c, "/a.Jpg", NULL), "\\.JPG$");
	ASSERT_STR(pick(c, "/a.gif", NULL), "\\.gif$");
	ASSERT_STR(pick(c, "/a.GIF", NULL), "-");
	bst_config_free(c);
}

TEST(nested_location)
{
	CFG(c, "location /api/ { location /api/v1/ { } location = /api/ping { } "
	       "location ~ ^/api/v\\d+/admin { } } location /other/ { }");
	ASSERT_STR(pick(c, "/api/x", NULL), "/api/");
	ASSERT_STR(pick(c, "/api/v1/users", NULL), "/api/v1/");
	ASSERT_STR(pick(c, "/api/ping", NULL), "/api/ping");
	ASSERT_STR(pick(c, "/api/v2/admin/x", NULL), "^/api/v\\d+/admin");
	ASSERT_STR(pick(c, "/other/api/v1/", NULL), "/other/");
	bst_config_free(c);
}

TEST(nested_outside_parent_refused)
{
	bst_config *c = comp("location /api/ { location /other/ { } }");
	ASSERT(c == NULL);
	ASSERT(strstr(E.msg, "is outside location") != NULL);
	ASSERT_EQ(E.line, 1);
	/* a regex child has no prefix to be outside of */
	c = comp("location /api/ { location ~ ^/x { } }");
	ASSERT(c != NULL);
	bst_config_free(c);
}

TEST(captures_available)
{
	CFG(c, "location ~ ^/u/([0-9]+)/(.*)$ { location /u/ { } }");
	bst_captures caps;
	ASSERT_STR(pick(c, "/u/42/photo", &caps), "/u/"); /* the child was chosen, the groups remain */
	ASSERT_EQ(caps.n, 3);
	ASSERT(bst_str_eq(bst_captures_get(&caps, 1), BST_S("42")));
	ASSERT(bst_str_eq(bst_captures_get(&caps, 2), BST_S("photo")));
	ASSERT_EQ(bst_captures_get(&caps, 3).len, 0);
	ASSERT_EQ(bst_captures_get(&caps, 9).len, 0);
	bst_config_free(c);
}

TEST(redos)
{
	CFG(c, "location ~ (a+)+$ { } location / { }");
	size_t n = 100000;
	char *uri = malloc(n + 4);
	ASSERT(uri != NULL);
	uri[0] = '/';
	memset(uri + 1, 'a', n);
	uri[n + 1] = 'b';
	uri[n + 2] = 0;
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	bst_captures caps;
	const char *r = pick(c, uri, &caps);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	double ms = (double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
	free(uri);
	ASSERT_STR(r, "LIMIT");
	ASSERT(caps.limit_hit);
	if (ms >= 50.0)
		TAP_FAIL_("took %.1f ms", ms);
	/* the next request is fine: the limit left nothing behind */
	ASSERT_STR(pick(c, "/aaa", NULL), "(a+)+$");
	ASSERT_STR(pick(c, "/bbb", NULL), "/");
	bst_config_free(c);
}

TEST(limits_are_configurable)
{
	CFG(c, "location ~ (a+)+$ { }");
	char uri[64] = "/";
	memset(uri + 1, 'a', 30);
	uri[31] = 'b';
	bst_regex_set_limits(100000000, 1000);
	/* 30 a's then b: exponential, but a huge limit and a small depth still end it */
	bst_regex_set_limits(200, 1000);
	ASSERT_STR(pick(c, uri, NULL), "LIMIT");
	bst_regex_set_limits(0, 0); /* back to the defaults */
	bst_config_free(c);
}

TEST(invalid_regex)
{
	bst_config *c = comp("\n\n  location ~ \"(unclosed\" { }");
	ASSERT(c == NULL);
	ASSERT(strstr(E.msg, "regular expression") != NULL);
	ASSERT_EQ(E.line, 3); /* the position of the location */
	ASSERT_EQ(E.col, 3);
	c = comp("name \"~(bad\";");
	ASSERT(c == NULL);
	ASSERT(strstr(E.msg, "regular expression") != NULL);
}

TEST(duplicate_location)
{
	bst_config *c = comp("location /a { } location /b { } location ^~ /a { }");
	ASSERT(c == NULL);
	ASSERT(strstr(E.msg, "duplicate location") != NULL);
	c = comp("location = /a { } location = /a { }");
	ASSERT(c == NULL);
	/* the same text as exact and as prefix are different locations */
	c = comp("location = /a { } location /a { }");
	ASSERT(c != NULL);
	bst_config_free(c);
}

TEST(many_prefixes_use_the_trie)
{
	char *body = malloc(400000);
	ASSERT(body != NULL);
	size_t w = 0;
	for (int i = 0; i < 6000; i++)
		w += (size_t)snprintf(body + w, 400000 - w, "location /p%d/ { } ", i);
	/* a long body does not fit comp's buffer: build the text here */
	char *text = malloc(w + 64);
	snprintf(text, w + 64, "server { listen 80; %s }", body);
	bst_arena_free(LAST);
	LAST = bst_arena_new(1 << 16);
	bst_ast *ast = bst_cfg_parse_string(text, strlen(text), "t.conf", NULL, LAST, &E);
	bst_config *c = ast ? bst_cfg_compile(ast, &E) : NULL;
	free(text);
	free(body);
	ASSERT(c != NULL);
	ASSERT_STR(pick(c, "/p5999/x", NULL), "/p5999/");
	ASSERT_STR(pick(c, "/p0/", NULL), "/p0/");
	ASSERT_STR(pick(c, "/p6000/", NULL), "-");
	bst_config_free(c);
}

TEST(no_locations)
{
	CFG(c, "return 200 x;");
	ASSERT_STR(pick(c, "/anything", NULL), "-");
	bst_config_free(c);
}

TAP_MAIN()

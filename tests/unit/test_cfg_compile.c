#include "config/compile.h"
#include "config/parser.h"
#include "config/schema.h"
#include "core/arena.h"
#include "tap.h"

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Fixture-only directives: they exist only in the explicit schema built here. */
static unsigned fx_calls, fx_fail_at;

static int ap_fail_nth(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d;
	if (++fx_calls == fx_fail_at) {
		bst_err_set(e, "injected failure %u", fx_calls);
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	return 0;
}

/* Appends the directive's argument to the inherited tag list in common. */
static int ap_tag(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	char *cp = bst_cfg_strdup(c, a->text, a->len, e);
	return cp ? bst_cfg_list_append(c, &c->common->tags, cp, e) : -1;
}

static int ap_noop(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)c, (void)d, (void)n, (void)e;
	return 0;
}

#define FXD(nm, ctx, ...) { .name = nm, .contexts = ctx, .doc = "fixture", __VA_ARGS__ }
static const bst_directive fx_dirs[] = {
	FXD("fail_nth", BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION, .apply = ap_fail_nth,
	    .repeatable = true),
#define STR1 .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_STRING } } }
	FXD("tag", BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION, .apply = ap_tag,
	    .repeatable = true, STR1),
	/* defaults: valid in server and location; location only; global and inheritable */
	FXD("dflt", BST_CTX_SERVER | BST_CTX_LOCATION, .apply = ap_tag, .default_value = "dflt",
	    STR1),
	FXD("ldef", BST_CTX_LOCATION, .apply = ap_tag, .default_value = "ldef", STR1),
	FXD("gdef", BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION, .apply = ap_tag,
	    .default_value = "gdef", STR1),
	/* Alternatives of one setting, and independent keys of one name. */
	FXD("balance", BST_CTX_SERVER, .apply = ap_noop, .subname = "peak_ewma",
	    .subname_exclusive = true),
	FXD("balance", BST_CTX_SERVER, .apply = ap_noop, .subname = "least_conn",
	    .subname_exclusive = true),
	FXD("tls", BST_CTX_SERVER, .apply = ap_noop, .subname = "verify",
	    .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_BOOL } } }),
	FXD("tls", BST_CTX_SERVER, .apply = ap_noop, .subname = "ca",
	    .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_PATH } } }),
};
static const bst_dirtab fx_tab = { fx_dirs, sizeof fx_dirs / sizeof fx_dirs[0] };

static bst_schema *SC;
static bst_err E;

static void init(void) __attribute__((constructor));
static void init(void)
{
	SC = bst_schema_build((const bst_dirtab *const[]){ bst_cfg_core_dirtab(), &fx_tab }, 2, &E);
	if (!SC) {
		fprintf(stderr, "schema: %s\n", E.msg);
		abort();
	}
}

/* Parses text into a fresh arena *a (the caller frees it) and compiles. */
static bst_config *compile_in(bst_arena **a, const char *text)
{
	*a = bst_arena_new(1 << 16);
	memset(&E, 0, sizeof E);
	bst_ast *ast = bst_cfg_parse_string(text, strlen(text), "t.conf", NULL, *a, &E);
	if (!ast)
		return NULL;
	return bst_cfg_compile_with(SC, ast, &E);
}

/* The AST stays alive until the next call, so E.file (which points into it) is readable. */
static bst_arena *LAST;
static bst_config *compile(const char *text)
{
	bst_arena_free(LAST);
	return compile_in(&LAST, text);
}

static bool err_has(const char *needle)
{
	return strstr(E.msg, needle) != NULL;
}

#define MB ((uint64_t)1 << 20)

TEST(inherit_scalar)
{
	bst_config *c = compile("server { listen 8080; client_max_body_size 5m;"
				" location /a { } }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT_EQ(s->common.client_max_body_size, 5 * MB);
	ASSERT_EQ(s->nlocations, 1);
	ASSERT_EQ(s->locations[0]->common.client_max_body_size, 5 * MB);
	bst_config_free(c);
}

TEST(child_overrides)
{
	bst_config *c = compile("server { listen 8080; client_max_body_size 5m;"
				" location /a { client_max_body_size 9k; } location /b { } }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT_EQ(s->common.client_max_body_size, 5 * MB);
	ASSERT_EQ(s->locations[0]->common.client_max_body_size, 9 * 1024);
	ASSERT_EQ(s->locations[1]->common.client_max_body_size, 5 * MB);
	bst_config_free(c);
}

TEST(defaults_applied)
{
	bst_config *c = compile("server { listen 8080; location / { } }");
	ASSERT(c != NULL);
	ASSERT(c->global.workers_auto);
	ASSERT(c->global.user == NULL && c->global.pid == NULL && c->global.error_log == NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT_EQ(s->common.client_max_body_size, MB);
	ASSERT_EQ(s->nnames, 0);
	ASSERT_EQ(s->locations[0]->common.client_max_body_size, MB);
	bst_config_free(c);
}

TEST(order_independent)
{
	bst_config *c = compile("server { location / { } location /b { client_max_body_size 2m; }"
				" client_max_body_size 7m; listen 8080; }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT_EQ(s->locations[0]->common.client_max_body_size, 7 * MB);
	ASSERT_EQ(s->locations[1]->common.client_max_body_size, 2 * MB);
	bst_config_free(c);
	/* Global directives after the servers still apply. */
	c = compile("server { listen 1; } workers 3; user nobody;");
	ASSERT(c != NULL);
	ASSERT(!c->global.workers_auto);
	ASSERT_EQ(c->global.workers, 3);
	ASSERT_STR(c->global.user, "nobody");
	bst_config_free(c);
}

TEST(global_directives)
{
	bst_config *c = compile("workers auto; pid /run/b.pid; error_log /var/e.log error;"
				" user bastion;");
	ASSERT(c != NULL);
	ASSERT(c->global.workers_auto);
	ASSERT_STR(c->global.pid, "/run/b.pid");
	ASSERT_STR(c->global.error_log, "/var/e.log");
	ASSERT_STR(c->global.error_log_level, "error");
	bst_config_free(c);
	c = compile("error_log /var/e.log;");
	ASSERT(c != NULL);
	ASSERT_STR(c->global.error_log_level, "warn");
	bst_config_free(c);
	ASSERT(compile("workers 0;") == NULL);
	ASSERT(compile("workers many;") == NULL);
}

TEST(no_listen)
{
	ASSERT(compile("server { }") == NULL);
	ASSERT(err_has("no \"listen\""));
	ASSERT_STR(E.file, "t.conf");
	ASSERT_EQ(E.line, 1);
	ASSERT_EQ(E.col, 1);
	ASSERT(err_has("listen 8080;"));
	ASSERT(compile("server { name a.com; location / { } }") == NULL);
}

TEST(duplicate_listener_name)
{
	ASSERT(compile("server { name a.com; listen 80; }\nserver { name a.com; listen 80; }") ==
	       NULL);
	ASSERT(err_has("duplicate listener 0.0.0.0:80"));
	ASSERT(err_has("\"a.com\""));
	ASSERT(err_has("first listen at t.conf:1:"));
	ASSERT_STR(E.file, "t.conf");
	ASSERT_EQ(E.line, 2);
	ASSERT(E.col > 0);
	/* Names are lower-cased before comparing. */
	ASSERT(compile("server { name A.com; listen 80; } server { name a.COM; listen 80; }") ==
	       NULL);
	/* One of several names shared. */
	ASSERT(compile("server { name a.com b.com; listen 80; } server { name b.com; listen 80; }")
	       == NULL);
	/* Two default servers on one address and port. */
	ASSERT(compile("server { listen 80; }\nserver { listen 80; }") == NULL);
	ASSERT(err_has("duplicate default server"));
	ASSERT_STR(E.file, "t.conf");
	ASSERT_EQ(E.line, 2);
	/* A repeated listen in one server is the same error. */
	ASSERT(compile("server { listen 80; listen 80; }") == NULL);

	bst_config *c = compile("server { name a.com; listen 80; } server { name b.com; listen 80; }"
				" server { name a.com; listen 81; }"
				" server { listen 10.0.0.1:80; } server { listen 80; }"
				" server { listen [::1]:80; } server { listen [::2]:80; }"
				" server { listen 127.0.0.1:80; } server { listen 0.0.0.0:81; }");
	ASSERT(c != NULL);
	ASSERT_EQ(c->global.nservers, 9);
	bst_config_free(c);
}

/* Equal listener keys are ordered by file position, not by where the arena put the servers:
 * with 3000 servers (several arena chunks) the first two to clash are reported in order. */
TEST(duplicate_listener_reports_file_order_across_chunks)
{
	enum { N = 3000 };
	char *src = malloc((size_t)N * 40 + 128), *p = src;
	for (int i = 0; i < N; i++)
		p += sprintf(p, "server { name h%d; listen 8080; }\n", i);
	p += sprintf(p, "server { name h1500; listen 8080; }\nserver { name h1500; listen 8080; }\n");
	ASSERT(compile(src) == NULL);
	ASSERT(err_has("duplicate listener 0.0.0.0:8080 for name \"h1500\""));
	ASSERT_EQ(E.line, N + 1);
	ASSERT(err_has(":1501:")); /* first listen: the original server, file order */
	free(src);
}

TEST(listen_forms)
{
	bst_config *c = compile("server { listen 8080; listen 10.1.2.3:443; listen [::1]:8443; }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT_EQ(s->nlistens, 3);
	ASSERT_EQ(s->listens[0].addr.port, 8080);
	ASSERT_EQ(s->listens[0].addr.ip.family, BST_IP_V4);
	ASSERT_EQ(s->listens[0].addr.ip.b[0], 0);
	ASSERT_EQ(s->listens[1].addr.port, 443);
	ASSERT_EQ(s->listens[1].addr.ip.b[0], 10);
	ASSERT_EQ(s->listens[1].addr.ip.b[3], 3);
	ASSERT_EQ(s->listens[2].addr.ip.family, BST_IP_V6);
	ASSERT_EQ(s->listens[2].addr.ip.b[15], 1);
	ASSERT_EQ(s->listens[2].addr.port, 8443);
	ASSERT_EQ(s->listens[2].loc.line, 1);
	bst_config_free(c);

	static const char *const bad[] = {
		"server { listen 0; }", "server { listen 65536; }", "server { listen 80x; }",
		"server { listen -1; }", "server { listen :80; }", "server { listen 1.2.3.4; }",
		"server { listen 1.2.3.4:; }", "server { listen 999.1.1.1:80; }",
		"server { listen ::1:80; }", "server { listen [::1]; }", "server { listen [::1:80; }",
		"server { listen [1.2.3.4]:80; }", "server { listen [::1]x80; }",
		"server { listen \"\"; }", "server { listen 080; }", "server { listen 127.0.0.1; }", "server { listen 1.2.3.4:99999999999999999999; }",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
		if (compile(bad[i]) != NULL)
			TAP_FAIL_("accepted: %s", bad[i]);
	/* Flags of later phases are not accepted silently: the schema allows one argument. */
	ASSERT(compile("server { listen 80 tls; }") == NULL);
	ASSERT(err_has("takes at most 1 argument"));
	ASSERT(compile("server { listen 80 http2; }") == NULL);
	ASSERT(compile("server { listen 80 tcp_profile=edge; }") == NULL);
	ASSERT(err_has("takes no options"));
}

TEST(name_directive)
{
	bst_config *c = compile("server { listen 80; name Example.COM www.example.com; name x.org; }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT_EQ(s->nnames, 3);
	ASSERT_STR(s->names[0], "example.com");
	ASSERT_STR(s->names[2], "x.org");
	bst_config_free(c);
	ASSERT(compile("server { listen 80; name a.com A.com; }") == NULL);
	ASSERT(err_has("duplicate server name"));
	ASSERT(compile("server { listen 80; name a.com; name a.com; }") == NULL);
	ASSERT(compile("server { listen 80; name \"\"; }") == NULL);
	/* The same name in different servers is fine when listeners differ. */
	c = compile("server { listen 80; name a.com; } server { listen 81; name a.com; }");
	ASSERT(c != NULL);
	bst_config_free(c);
}

/* Many names in one server: duplicates are found by sorting, not by a scan per name (80k names
 * took seconds that way), and the error lands on the second occurrence. */
TEST(many_names_duplicate_scan_is_not_quadratic)
{
	enum { N = 80000 };
	char *src = malloc((size_t)N * 20 + 64), *p = src;
	p += sprintf(p, "server { listen 80;\n");
	for (int i = 0; i < N; i++)
		p += sprintf(p, "name n%d;\n", i);
	char *ok_end = p;
	p += sprintf(p, "name n12345;\n}\n"); /* duplicate of line 12347 (1 + 12345 + 1) */
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	bst_config *c = compile(src);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	double secs = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
	ASSERT(c == NULL);
	ASSERT(err_has("duplicate server name \"n12345\""));
	ASSERT_EQ(E.line, N + 2);
	ASSERT_EQ(E.col, 6);
	ASSERT(secs < 1.5);
	strcpy(ok_end, "}\n");
	c = compile(src);
	ASSERT(c != NULL);
	ASSERT_EQ(c->global.servers[0]->nnames, N);
	bst_config_free(c);
	free(src);
}

TEST(location_forms)
{
	bst_config *c = compile("server { listen 80; location /a { } location = /b { }"
				" location ^~ /c { } location ~ \"^/d\" { } location ~* \\.x$ { } }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT_EQ(s->nlocations, 5);
	ASSERT_EQ(s->locations[0]->mod, BST_LOC_PREFIX);
	ASSERT_STR(s->locations[0]->pattern, "/a");
	ASSERT_EQ(s->locations[1]->mod, BST_LOC_EXACT);
	ASSERT_EQ(s->locations[2]->mod, BST_LOC_PREFIX_STOP);
	ASSERT_EQ(s->locations[3]->mod, BST_LOC_REGEX);
	ASSERT_STR(s->locations[3]->pattern, "^/d");
	ASSERT_EQ(s->locations[4]->mod, BST_LOC_REGEX_I);
	bst_config_free(c);
	ASSERT(compile("server { listen 80; location =~ /x { } }") == NULL);
	ASSERT(err_has("invalid location modifier"));
	ASSERT(compile("server { listen 80; location ^~ { } }") == NULL);
	ASSERT(err_has("needs a pattern"));
	ASSERT(compile("server { listen 80; location /a /b { } }") == NULL);
	ASSERT(err_has("invalid location modifier"));
	ASSERT(compile("server { listen 80; location = { } }") == NULL);
	ASSERT(compile("server { listen 80; location ~ \"\" { } }") == NULL);
	ASSERT(compile("server { listen 80; location a b c { } }") == NULL);
}

/* Long file names must not cost the primary position (it is in err, not the message). */
TEST(error_position_long_path)
{
	char name[200];
	memset(name, 'p', sizeof name - 1);
	name[sizeof name - 1] = 0;
	const char *src = "server { name a.com; listen 80; }\nserver { name a.com; listen 80; }\n";
	bst_arena *a = bst_arena_new(1 << 16);
	bst_ast *ast = bst_cfg_parse_string(src, strlen(src), name, NULL, a, &E);
	ASSERT(ast != NULL);
	ASSERT(bst_cfg_compile_with(SC, ast, &E) == NULL);
	ASSERT(E.file != NULL && strcmp(E.file, name) == 0);
	ASSERT_EQ(E.line, 2);
	ASSERT(E.col > 0);
	ASSERT(strstr(E.msg, "duplicate listener") != NULL);
	src = "server { }\n";
	ast = bst_cfg_parse_string(src, strlen(src), name, NULL, a, &E);
	ASSERT(ast != NULL);
	ASSERT(bst_cfg_compile_with(SC, ast, &E) == NULL);
	ASSERT(E.file != NULL && strcmp(E.file, name) == 0);
	ASSERT_EQ(E.line, 1);
	bst_arena_free(a);
}

TEST(nested_location)
{
	/* inherit, override, order independence, three levels */
	bst_config *c = compile("server { listen 80;\n"
				"  location /a { location /a/b { location /a/b/c { } }\n"
				"                client_max_body_size 3m;\n"
				"                location /a/o { client_max_body_size 4m; } }\n"
				"  client_max_body_size 2m; }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT_EQ(s->nlocations, 1);
	const bst_cfg_location *a = s->locations[0];
	ASSERT(a->parent == NULL);
	ASSERT_EQ(a->common.client_max_body_size, 3 * MB);
	ASSERT_EQ(a->nchildren, 2);
	const bst_cfg_location *b = a->children[0], *o = a->children[1];
	ASSERT(b->parent == a && o->parent == a);
	ASSERT_STR(b->pattern, "/a/b");
	ASSERT_EQ(b->common.client_max_body_size, 3 * MB);
	ASSERT_EQ(o->common.client_max_body_size, 4 * MB);
	ASSERT_EQ(b->nchildren, 1);
	const bst_cfg_location *cc = b->children[0];
	ASSERT(cc->parent == b);
	ASSERT_EQ(cc->common.client_max_body_size, 3 * MB);
	bst_config_free(c);
	ASSERT(compile("server { listen 80; location /a { location ^~ { } } }") == NULL);
}

TEST(regex_names_keep_case)
{
	bst_config *c = compile("server { listen 80; name Foo.com ~^Foo\\D$ ~A ~a; }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT_EQ(s->nnames, 4);
	ASSERT_STR(s->names[0], "foo.com");
	ASSERT_STR(s->names[1], "~^Foo\\D$");
	ASSERT_STR(s->names[2], "~A");
	ASSERT_STR(s->names[3], "~a"); /* distinct as stored */
	bst_config_free(c);
	ASSERT(compile("server { listen 80; name ~A ~A; }") == NULL);
}

static bool tags_are(const bst_cfg_list *l, const char *const *want, size_t n)
{
	if (l->n != n)
		return false;
	for (size_t i = 0; i < n; i++)
		if (strcmp(l->items[i], want[i]) != 0)
			return false;
	return true;
}

/* A list in common, with the replace semantics (the first statement in a scope replaces what
 * the scope inherited): siblings must not see or disturb each other or the parent. The
 * defaults dflt, ldef and gdef append to the same list in the scope where they are valid.
 * test_cfg_engine.c covers append, extend and default replacement in isolation. */
TEST(inherited_list_append)
{
	bst_config *c = compile("tag g1; server { listen 80; tag s1;\n"
				"  location /a { tag a1; tag a2; location /a/x { tag x1; } }\n"
				"  location /b { tag b1; } location /c { } }");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	static const char *const sv[] = { "dflt", "s1" };
	static const char *const la[] = { "ldef", "a1", "a2" };
	static const char *const lx[] = { "x1" };
	static const char *const lb[] = { "ldef", "b1" };
	static const char *const lc[] = { "ldef" };
	ASSERT(tags_are(&s->common.tags, sv, 2));
	ASSERT(tags_are(&s->locations[0]->common.tags, la, 3));
	ASSERT(tags_are(&s->locations[0]->children[0]->common.tags, lx, 1));
	ASSERT(tags_are(&s->locations[1]->common.tags, lb, 2));
	ASSERT(tags_are(&s->locations[2]->common.tags, lc, 1));
	ASSERT(tags_are(&c->global.common.tags, (const char *const[]){ "gdef", "g1" }, 2));
	bst_config_free(c);
}

TEST(subname_exclusive)
{
	bst_arena *a;
	ASSERT(compile_in(&a, "server { listen 80;\n balance peak_ewma;\n balance least_conn; }") ==
	       NULL);
	bst_arena_free(a);
	ASSERT(err_has("duplicate \"balance\""));
	ASSERT(err_has("first at t.conf:2:"));
	ASSERT_EQ(E.line, 3);
	/* Independent subnames of one name are still allowed. */
	bst_config *c = compile("server { listen 80; tls verify on; tls ca /x; balance peak_ewma; }");
	ASSERT(c != NULL);
	bst_config_free(c);
	ASSERT(compile("server { listen 80; tls verify on; tls verify off; }") == NULL);
	ASSERT(err_has("duplicate \"tls verify\""));
	/* The flag is meaningless without a subname. */
	static const bst_directive bad[] = {
		{ .name = "x", .contexts = BST_CTX_SERVER, .doc = "d", .apply = ap_noop,
		  .subname_exclusive = true },
	};
	bst_dirtab t = { bad, 1 };
	ASSERT(bst_schema_build((const bst_dirtab *const[]){ &t }, 1, &E) == NULL);
}

TEST(hints)
{
	bst_arena *a = bst_arena_new(1 << 16);
	const char *src = "server { listen 80; listen 81 tcp_profile=x; }";
	bst_ast *ast = bst_cfg_parse_string(src, strlen(src), "t.conf", NULL, a, &E);
	ASSERT(ast != NULL);
	ASSERT(bst_cfg_validate_with(SC, ast, &E) != 0);
	ASSERT(err_has("(quote the word to use it literally)"));
	bst_arena_free(a);
	a = bst_arena_new(1 << 16);
	src = "root /a\"b\";";
	ASSERT(bst_cfg_parse_string(src, strlen(src), "t.conf", NULL, a, &E) == NULL);
	ASSERT(err_has("quote inside bare word; quote the whole word, e.g. \"path=/a b\""));
	bst_arena_free(a);
}

/* The compiled config owns everything: free (so poison, under ASan) the AST arena, then
 * read every string. */
TEST(independent_of_ast)
{
	bst_arena *a;
	bst_config *c = compile_in(&a, "user bastion; pid /run/b.pid; error_log /var/log/e.log info;\n"
					"server { name Example.com; listen 10.0.0.1:80;\n"
					"  location ~* \"^/img/\" { client_max_body_size 3m; } }");
	ASSERT(c != NULL);
	bst_arena_free(a);
	ASSERT_STR(c->global.user, "bastion");
	ASSERT_STR(c->global.pid, "/run/b.pid");
	ASSERT_STR(c->global.error_log, "/var/log/e.log");
	ASSERT_STR(c->global.error_log_level, "info");
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT_STR(s->names[0], "example.com");
	ASSERT_STR(s->loc.file, "t.conf");
	ASSERT_STR(s->listens[0].loc.file, "t.conf");
	ASSERT_STR(s->locations[0]->pattern, "^/img/");
	ASSERT_STR(s->locations[0]->loc.file, "t.conf");
	ASSERT_EQ(s->locations[0]->common.client_max_body_size, 3 * MB);
	bst_config_free(c);
}

TEST(simple_site_shape)
{
	bst_config *c = compile(
		"user bastion;\nworkers auto;\npid /run/bastion.pid;\n"
		"error_log /var/log/bastion/error.log warn;\n"
		"server {\n  name example.com www.example.com;\n  listen 80;\n  listen [::]:80;\n"
		"  client_max_body_size 10m;\n"
		"  location / { }\n  location ^~ /assets/ { client_max_body_size 0; }\n"
		"  location /api/ { }\n  location = /login { }\n"
		"  location ~ \"^/old/(.+)$\" { }\n}\n");
	ASSERT(c != NULL);
	const bst_cfg_server *s = c->global.servers[0];
	ASSERT_EQ(s->nnames, 2);
	ASSERT_EQ(s->nlistens, 2);
	ASSERT_EQ(s->nlocations, 5);
	ASSERT_EQ(s->locations[1]->common.client_max_body_size, 0);
	ASSERT_EQ(s->locations[2]->common.client_max_body_size, 10 * MB);
	bst_config_free(c);
}

TEST(registry_compile)
{
	bst_arena *a = bst_arena_new(1 << 16);
	const char *src = "workers 2; server { listen 8080; client_max_body_size 2k; }";
	bst_ast *ast = bst_cfg_parse_string(src, strlen(src), "t.conf", NULL, a, &E);
	ASSERT(ast != NULL);
	bst_config *c = bst_cfg_compile(ast, &E);
	ASSERT(c != NULL);
	ASSERT_EQ(c->global.servers[0]->common.client_max_body_size, 2048);
	bst_config_free(c);
	/* Directives of later phases are validation errors until they register. */
	src = "server { listen 80; proxy http://x; }";
	ast = bst_cfg_parse_string(src, strlen(src), "t.conf", NULL, a, &E);
	ASSERT(ast != NULL);
	ASSERT(bst_cfg_compile(ast, &E) == NULL);
	ASSERT(err_has("proxy"));
	bst_arena_free(a);
	bst_config_free(NULL);
}

static size_t count_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	size_t n = 0;
	if (!d)
		return 0;
	while (readdir(d))
		n++;
	closedir(d);
	return n;
}

#define SWEEP_CFG                                                                       \
	"fail_nth;\n"                                                                   \
	"server { name a.com; listen 8080; fail_nth; location /x { fail_nth; }\n"       \
	"  location /y { fail_nth; } }\n"                                               \
	"server { name b.com; listen 8081; fail_nth; location /z { fail_nth; } }\n"     \
	"fail_nth;\n"

/* A failure injected at each apply in turn: LeakSanitizer must stay quiet (it runs at
 * exit under the asan build) and no fd may be left open. */
TEST(compile_failure_no_leak)
{
	size_t fds = count_fds();
	unsigned n;
	for (n = 1; n < 40; n++) {
		bst_arena *a;
		fx_calls = 0;
		fx_fail_at = n;
		bst_config *c = compile_in(&a, SWEEP_CFG);
		bst_arena_free(a);
		if (c != NULL) {
			bst_config_free(c);
			break;
		}
		if (!err_has("injected failure"))
			TAP_FAIL_("n=%u: unexpected error: %s", n, E.msg);
	}
	fx_fail_at = 0;
	ASSERT_EQ(n, 8); /* seven fixture applies fail, the eighth run succeeds */
	/* Failures in the cross-block checks and in core applies leave nothing behind too. */
	ASSERT(compile("server { }") == NULL);
	ASSERT(compile("server { listen 80; } server { listen 80; }") == NULL);
	ASSERT(compile("server { listen 80; name a b a; location /q { } }") == NULL);
	ASSERT_EQ(count_fds(), fds);
}

/* Reload: a failed compile must leave the running config untouched and readable. */
TEST(failed_compile_keeps_old)
{
	bst_config *old = compile("user u; server { name a.com; listen 8080; client_max_body_size 4m;"
				  " location /p { } }");
	ASSERT(old != NULL);
	fx_calls = 0;
	fx_fail_at = 3;
	ASSERT(compile(SWEEP_CFG) == NULL);
	fx_fail_at = 0;
	ASSERT(compile("server { listen 80; } server { listen 80; }") == NULL);
	ASSERT(compile("server { listen 80x; }") == NULL);
	ASSERT_STR(old->global.user, "u");
	const bst_cfg_server *s = old->global.servers[0];
	ASSERT_STR(s->names[0], "a.com");
	ASSERT_EQ(s->listens[0].addr.port, 8080);
	ASSERT_EQ(s->common.client_max_body_size, 4 * MB);
	ASSERT_STR(s->locations[0]->pattern, "/p");
	bst_config_free(old);
}

TAP_MAIN()

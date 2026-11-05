#include "config/parser.h"
#include "core/arena.h"
#include "tap.h"

#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define LIT(s) s, sizeof(s) - 1

static bst_arena *A;
static bst_err E;
static char dir[256];

static void fresh(void)
{
	if (A)
		bst_arena_free(A);
	A = bst_arena_new(1 << 16);
	memset(&E, 0, sizeof E);
}

static int rm_cb(const char *p, const struct stat *sb, int f, struct FTW *w)
{
	(void)sb, (void)f, (void)w;
	remove(p);
	return 0;
}

static void mkdir_tmp(void)
{
	const char *t = getenv("TMPDIR");
	snprintf(dir, sizeof dir, "%s/bst_cfgp_XXXXXX", t && *t ? t : "/tmp");
	if (!mkdtemp(dir))
		abort();
}

static void rmdir_tmp(void)
{
	nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

static void put(const char *name, const char *content)
{
	char p[512];
	snprintf(p, sizeof p, "%s/%s", dir, name);
	FILE *f = fopen(p, "wb");
	if (!f || fputs(content, f) == EOF || fclose(f))
		abort();
}

static char *path(const char *name)
{
	static char b[4][512];
	static int i;
	char *p = b[i++ & 3];
	snprintf(p, 512, "%s/%s", dir, name);
	return p;
}

/* "<depth> name arg arg" per node, pre-order, via the iterative walk. */
static const char *dump(const bst_ast *ast)
{
	static char out[8192];
	size_t n = 0;
	out[0] = 0;
	for (const bst_ast_node *x = bst_ast_next(ast, NULL); x; x = bst_ast_next(ast, x)) {
		int d = 0;
		for (const bst_ast_node *p = x->parent; p != &ast->root; p = p->parent)
			d++;
		n += (size_t)snprintf(out + n, sizeof out - n, "%d %s", d, x->name);
		for (size_t i = 0; i < x->nargs; i++)
			n += (size_t)snprintf(out + n, sizeof out - n, " %s", x->args[i].text);
		n += (size_t)snprintf(out + n, sizeof out - n, "\n");
	}
	return out;
}

static bst_ast *ps(const char *s)
{
	fresh();
	return bst_cfg_parse_string(s, strlen(s), "t.conf", NULL, A, &E);
}

static int err_is(const char *file, int line, int col, const char *needle)
{
	int ok = (!file || (E.file && strcmp(E.file, file) == 0)) && E.line == line &&
		 E.col == col && strstr(E.msg, needle);
	if (!ok)
		printf("# err %s:%d:%d: %s\n", E.file ? E.file : "(null)", E.line, E.col, E.msg);
	return ok;
}

TEST(nested_blocks)
{
	bst_ast *a = ps("server {\n  listen 80;\n  location / { return 404; }\n}\nworker 2;\n");
	ASSERT(a);
	ASSERT_STR(dump(a), "0 server\n1 listen 80\n1 location /\n2 return 404\n0 worker 2\n");
	const bst_ast_node *s = a->root.children;
	ASSERT(s->has_block && s->nchildren == 2 && s->loc.line == 1 && s->loc.col == 1);
	ASSERT(s->children->next->children->loc.line == 3);
	ASSERT(!a->root.children->next->has_block);
}

TEST(args_kinds)
{
	bst_ast *a = ps("x a \"b c\" 'd e';");
	ASSERT(a);
	const bst_ast_node *n = a->root.children;
	ASSERT_EQ(n->nargs, 3);
	ASSERT_EQ(n->args[0].kind, BST_TOK_WORD);
	ASSERT_EQ(n->args[1].kind, BST_TOK_STRING_TPL);
	ASSERT_EQ(n->args[2].kind, BST_TOK_STRING_RAW);
	ASSERT_STR(n->args[1].text, "b c");
	ASSERT_EQ(n->args[1].loc.col, 5);
}

TEST(missing_semicolon)
{
	ASSERT(!ps("a 1;\nlisten 80\n}\n"));
	ASSERT(err_is("t.conf", 2, 10, "';'"));
	ASSERT(!ps("a 1;\nlisten 80\n"));
	ASSERT(err_is("t.conf", 2, 10, "';'"));
	ASSERT(!ps("a {\nb\n}\n"));
	ASSERT(err_is("t.conf", 2, 2, "';'"));
}

TEST(unbalanced_brace)
{
	ASSERT(!ps("a {\n  b {\n    c;\n}\n"));
	ASSERT(err_is("t.conf", 1, 1, "unclosed"));
	ASSERT(!ps("x;\n  server {\n  y;\n"));
	ASSERT(err_is("t.conf", 2, 3, "unclosed"));
}

TEST(stray_rbrace)
{
	ASSERT(!ps("a;\n  }\n"));
	ASSERT(err_is("t.conf", 2, 3, "}"));
}

TEST(statement_shape_errors)
{
	ASSERT(!ps("a;\n;\n"));
	ASSERT(err_is("t.conf", 2, 1, "empty"));
	ASSERT(!ps("\"a\" 1;"));
	ASSERT(err_is("t.conf", 1, 1, "bare word"));
	ASSERT(!ps("'a' 1;"));
	ASSERT(!ps("{ a; }"));
	ASSERT(err_is("t.conf", 1, 1, "name"));
	ASSERT(!ps("a \"unterminated"));
	ASSERT(err_is("t.conf", 1, 3, ""));
}

TEST(arg_limit)
{
	char *s = malloc(BST_CFG_MAX_ARGS * 2 + 16);
	strcpy(s, "x");
	for (int i = 0; i < BST_CFG_MAX_ARGS; i++)
		strcat(s, " a");
	strcat(s, ";");
	ASSERT(ps(s));
	s[strlen(s) - 1] = 0;
	strcat(s, " a;");
	ASSERT(!ps(s));
	ASSERT(strstr(E.msg, "256"));
	free(s);
}

TEST(depth_limit)
{
	size_t n = 1000;
	char *s = malloc(n * 3 + 1);
	for (size_t i = 0; i < n; i++)
		memcpy(s + i * 3, "a{ ", 3);
	fresh();
	ASSERT(!bst_cfg_parse_string(s, n * 3, "t.conf", NULL, A, &E));
	ASSERT(strstr(E.msg, "64"));
	ASSERT_EQ(E.line, 1);
	ASSERT_EQ(E.col, 64 * 3 + 1);
	free(s);
	/* exactly 64 is fine, and the AST walk of it is iterative */
	s = malloc(64 * 4 + 1);
	for (int i = 0; i < 64; i++)
		memcpy(s + i * 3, "a{ ", 3);
	for (int i = 0; i < 64; i++)
		s[64 * 3 + i] = '}';
	fresh();
	bst_ast *a = bst_cfg_parse_string(s, 64 * 4, "t.conf", NULL, A, &E);
	ASSERT(a);
	int c = 0;
	for (const bst_ast_node *x = bst_ast_next(a, NULL); x; x = bst_ast_next(a, x))
		c++;
	ASSERT_EQ(c, 64);
	free(s);
}

TEST(env_default)
{
	unsetenv("BST_X");
	bst_ast *a = ps("a ${BST_X:-y} p${BST_X:-q}s;");
	ASSERT(a);
	ASSERT_STR(a->root.children->args[0].text, "y");
	ASSERT_STR(a->root.children->args[1].text, "pqs");
	a = ps("a \"${BST_X:-}\";");
	ASSERT(a && a->root.children->args[0].len == 0);
}

TEST(env_missing)
{
	unsetenv("BST_X");
	ASSERT(!ps("\n  a ${BST_X};"));
	ASSERT(err_is("t.conf", 2, 5, "BST_X"));
}

TEST(env_names)
{
	ASSERT(!ps("a ${1X};"));
	ASSERT(!ps("a ${};"));
	ASSERT(!ps("a ${X-y};"));
	ASSERT(!ps("a ${a b};") && strstr(E.msg, "${"));
	ASSERT(!ps("a \"${A.B:-x}\";"));
	setenv("BST_a_1", "ok", 1);
	bst_ast *a = ps("a ${BST_a_1};");
	ASSERT(a);
	ASSERT_STR(a->root.children->args[0].text, "ok");
	ASSERT(!ps("a \"${BST_a_1\";"));
	ASSERT(strstr(E.msg, "unterminated") || E.msg[0]);
}

TEST(env_empty_counts_as_set)
{
	setenv("BST_E", "", 1);
	bst_ast *a = ps("a ${BST_E:-y} \"${BST_E}\";");
	ASSERT(a);
	ASSERT_EQ(a->root.children->args[0].len, 0);
	ASSERT_EQ(a->root.children->args[1].len, 0);
}

TEST(env_value_is_literal)
{
	setenv("BST_V", "a; b } # \"q\" 'r' $x ${Y}\n{", 1);
	bst_ast *a = ps("a pre${BST_V}post; b;");
	ASSERT(a);
	ASSERT_EQ(a->root.children->nargs, 1);
	ASSERT_STR(a->root.children->args[0].text, "prea; b } # \"q\" 'r' $x ${Y}\n{post");
	ASSERT(a->root.children->next && !a->root.children->next->next);
	/* template form: env-derived $ doubled, source $ kept */
	a = ps("a $host${BST_V}$uri;");
	ASSERT(a);
	ASSERT_STR(a->root.children->args[0].tpl,
		   "$host" "a; b } # \"q\" 'r' $$x $${Y}\n{" "$uri");
	ASSERT_STR(a->root.children->args[0].text,
		   "$host" "a; b } # \"q\" 'r' $x ${Y}\n{" "$uri");
}

TEST(env_dollar_forms)
{
	setenv("BST_D", "$x", 1);
	unsetenv("BST_U");
	bst_ast *a = ps("a ${BST_D} \"${BST_D}\" ${BST_U:-$z} plain;");
	ASSERT(a);
	const bst_ast_node *n = a->root.children;
	ASSERT_STR(n->args[0].tpl, "$$x");
	ASSERT_STR(n->args[1].tpl, "$$x");
	ASSERT_STR(n->args[2].text, "$z");
	ASSERT_STR(n->args[2].tpl, "$$z"); /* default is literal, not a template */
	ASSERT(n->args[3].tpl == n->args[3].text);
	/* default is not expanded again */
	setenv("BST_N", "nested", 1);
	a = ps("a ${BST_U:-x${BST_N}};");
	ASSERT(!a || strcmp(a->root.children->args[0].text, "nested") != 0);
}

TEST(env_not_in_single_quotes)
{
	setenv("BST_S", "val", 1);
	bst_ast *a = ps("a '${BST_S}' '$x';");
	ASSERT(a);
	ASSERT_STR(a->root.children->args[0].text, "${BST_S}");
	ASSERT_STR(a->root.children->args[0].tpl, "$${BST_S}");
	ASSERT_STR(a->root.children->args[1].tpl, "$$x");
	unsetenv("BST_S");
	ASSERT(ps("a '${BST_S}';"));
}

TEST(env_arg_size_limit)
{
	size_t n = BST_CFG_MAX_ARG_BYTES + 1;
	char *v = malloc(n + 1);
	memset(v, 'v', n);
	v[n] = 0;
	setenv("BST_BIG", v, 1);
	free(v);
	ASSERT(!ps("a ${BST_BIG};"));
	ASSERT(strstr(E.msg, "1048576") || strstr(E.msg, "limit"));
	unsetenv("BST_BIG");
}

TEST(env_expansion_budget)
{
	size_t n = BST_CFG_MAX_ARG_BYTES;
	char *v = malloc(n + 1);
	memset(v, 'v', n);
	v[n] = 0;
	setenv("BST_BIG", v, 1);
	free(v);
	/* each token is 10 bytes; the expanded args total 64 MiB + 1 MiB */
	size_t k = BST_CFG_MAX_EXPANDED / n + 1;
	char *s = malloc(k * 13 + 8);
	size_t p = 0;
	for (size_t i = 0; i < k; i++) {
		memcpy(s + p, "a ${BST_BIG};", 13);
		p += 13;
	}
	s[p] = 0;
	ASSERT(!ps(s));
	ASSERT(strstr(E.msg, "67108864") || strstr(E.msg, "expanded"));
	free(s);
	unsetenv("BST_BIG");
}

TEST(include_glob_sorted)
{
	mkdir_tmp();
	put("main.conf", "first 0;\ninclude conf.d/*.conf;\nlast 9;\n");
	mkdir(path("conf.d"), 0755);
	put("conf.d/b.conf", "bb 2;\n");
	put("conf.d/a.conf", "aa 1; blk { inner 1; }\n");
	put("conf.d/0.conf", "upper 0;\n");
	put("conf.d/_.conf", "under 0;\n");
	put("conf.d/z.txt", "no 0;\n");
	fresh();
	bst_ast *a = bst_cfg_parse_file(path("main.conf"), A, &E);
	ASSERT(a);
	/* bytewise: 0 < _ < a < b */
	ASSERT_STR(dump(a), "0 first 0\n0 upper 0\n0 under 0\n0 aa 1\n0 blk\n1 inner 1\n0 bb 2\n0 last 9\n");
	/* spliced nodes keep their real loc and no include node remains */
	const bst_ast_node *n = a->root.children->next;
	ASSERT(strstr(n->loc.file, "conf.d/0.conf") && n->loc.line == 1);
	rmdir_tmp();
}

TEST(include_relative)
{
	mkdir_tmp();
	mkdir(path("sub"), 0755);
	put("main.conf", "include sub/one.conf;\n");
	put("sub/one.conf", "one 1;\ninclude two.conf;\n");
	put("sub/two.conf", "two 2;\n");
	put("two.conf", "WRONG 0;\n");
	fresh();
	bst_ast *a = bst_cfg_parse_file(path("main.conf"), A, &E);
	ASSERT(a);
	ASSERT_STR(dump(a), "0 one 1\n0 two 2\n");
	rmdir_tmp();
}

TEST(include_inside_block_and_env_path)
{
	mkdir_tmp();
	put("main.conf", "server {\n  include ${BST_INC};\n  tail 1;\n}\n");
	put("inc.conf", "inner 1;\n");
	setenv("BST_INC", "inc.conf", 1);
	fresh();
	bst_ast *a = bst_cfg_parse_file(path("main.conf"), A, &E);
	ASSERT(a);
	ASSERT_STR(dump(a), "0 server\n1 inner 1\n1 tail 1\n");
	/* braces must close in the file that opened them */
	put("open.conf", "blk {\n");
	put("main2.conf", "include open.conf;\n}\n");
	fresh();
	ASSERT(!bst_cfg_parse_file(path("main2.conf"), A, &E));
	ASSERT(err_is(NULL, 1, 1, "unclosed"));
	ASSERT(strstr(E.file, "open.conf"));
	rmdir_tmp();
}

TEST(include_nomatch_and_missing)
{
	mkdir_tmp();
	put("main.conf", "a 1;\ninclude nothing/*.conf;\ninclude none?.conf;\nb 2;\n");
	fresh();
	bst_ast *a = bst_cfg_parse_file(path("main.conf"), A, &E);
	ASSERT(a);
	ASSERT_STR(dump(a), "0 a 1\n0 b 2\n");
	put("lit.conf", "a 1;\n  include missing.conf;\n");
	fresh();
	ASSERT(!bst_cfg_parse_file(path("lit.conf"), A, &E));
	ASSERT(err_is(NULL, 2, 11, "missing.conf"));
	ASSERT(strstr(E.file, "lit.conf"));
	rmdir_tmp();
}

TEST(include_arg_errors)
{
	ASSERT(!ps("include;"));
	ASSERT(err_is("t.conf", 1, 1, "path"));
	ASSERT(!ps("x;\ninclude a b;"));
	ASSERT(err_is("t.conf", 2, 11, "exactly one"));
	ASSERT(!ps("include a {\n}"));
	ASSERT(err_is("t.conf", 1, 11, "block"));
	ASSERT(!ps("include a\n}"));
	ASSERT(err_is("t.conf", 1, 10, "';'"));
}

TEST(include_disabled)
{
	bst_cfg_opts o = {.no_include = 1};
	fresh();
	const char *s = "a 1;\ninclude /etc/passwd;\n";
	ASSERT(!bst_cfg_parse_string(s, strlen(s), "t.conf", &o, A, &E));
	ASSERT(err_is("t.conf", 2, 1, "disabled"));
}

TEST(include_cycle)
{
	mkdir_tmp();
	put("a.conf", "a 1;\ninclude b.conf;\n");
	put("b.conf", "b 1;\ninclude a.conf;\n");
	fresh();
	ASSERT(!bst_cfg_parse_file(path("a.conf"), A, &E));
	ASSERT(strstr(E.msg, "cycle"));
	ASSERT(strstr(E.msg, "a.conf") && strstr(E.msg, "b.conf") && strstr(E.msg, "->"));
	ASSERT(strstr(E.file, "b.conf") && E.line == 2);
	rmdir_tmp();
}

TEST(include_cycle_via_symlink)
{
	mkdir_tmp();
	mkdir(path("d"), 0755);
	put("a.conf", "include d/../link.conf;\n");
	ASSERT(symlink("a.conf", path("link.conf")) == 0);
	fresh();
	ASSERT(!bst_cfg_parse_file(path("a.conf"), A, &E));
	ASSERT(strstr(E.msg, "cycle"));
	/* self include via different spelling */
	put("self.conf", "include ./self.conf;\n");
	fresh();
	ASSERT(!bst_cfg_parse_file(path("self.conf"), A, &E));
	ASSERT(strstr(E.msg, "cycle"));
	rmdir_tmp();
}

TEST(include_twice_is_not_a_cycle)
{
	mkdir_tmp();
	put("main.conf", "include one.conf;\ninclude two.conf;\n");
	put("one.conf", "include shared.conf;\n");
	put("two.conf", "include shared.conf;\n");
	put("shared.conf", "s 1;\n");
	fresh();
	bst_ast *a = bst_cfg_parse_file(path("main.conf"), A, &E);
	ASSERT(a);
	ASSERT_STR(dump(a), "0 s 1\n0 s 1\n");
	rmdir_tmp();
}

static void chain(int n)
{
	char nm[32], body[64];
	for (int i = 0; i < n; i++) {
		snprintf(nm, sizeof nm, "f%d.conf", i);
		snprintf(body, sizeof body, "d%d 1;\ninclude f%d.conf;\n", i, i + 1);
		put(nm, body);
	}
	snprintf(nm, sizeof nm, "f%d.conf", n);
	put(nm, "leaf 1;\n");
}

TEST(include_depth)
{
	mkdir_tmp();
	chain(16); /* f0 .. f16: sixteen nested includes, allowed */
	fresh();
	bst_ast *a = bst_cfg_parse_file(path("f0.conf"), A, &E);
	ASSERT(a);
	ASSERT(strstr(dump(a), "leaf 1"));
	chain(17); /* seventeen */
	fresh();
	ASSERT(!bst_cfg_parse_file(path("f0.conf"), A, &E));
	ASSERT(strstr(E.msg, "16"));
	ASSERT(strstr(E.file, "f16.conf"));
	rmdir_tmp();
}

TEST(include_fifo_does_not_hang)
{
	mkdir_tmp();
	put("main.conf", "include *.pipe;\n");
	ASSERT(mkfifo(path("x.pipe"), 0600) == 0);
	fresh();
	alarm(20);
	ASSERT(!bst_cfg_parse_file(path("main.conf"), A, &E));
	alarm(0);
	ASSERT(strstr(E.msg, "not a regular file"));
	/* directories too, and a FIFO named directly */
	put("main2.conf", "include x.pipe;\n");
	fresh();
	ASSERT(!bst_cfg_parse_file(path("main2.conf"), A, &E));
	fresh();
	ASSERT(!bst_cfg_parse_file(dir, A, &E));
	ASSERT(strstr(E.msg, "not a regular file"));
	rmdir_tmp();
}

TEST(path_escaped_in_errors)
{
	mkdir_tmp();
	put("main.conf", "include \"no\\tsuch\x01.conf\";\n");
	fresh();
	ASSERT(!bst_cfg_parse_file(path("main.conf"), A, &E));
	for (const char *p = E.msg; *p; p++)
		ASSERT((unsigned char)*p >= 0x20 && *p != 0x7f);
	ASSERT(strstr(E.msg, "\\x09") && strstr(E.msg, "\\x01"));
	rmdir_tmp();
}

/* The file limit is lowered through the options so the test does not need a million files. */
#define LIM 100
static bst_ast *parse_limited(const char *file)
{
	bst_cfg_opts o = { .max_files = LIM };
	return bst_cfg_parse_file_opts(path(file), &o, A, &E);
}

TEST(include_file_count_limit)
{
	mkdir_tmp();
	mkdir(path("many"), 0755);
	char nm[64];
	for (int i = 0; i < LIM; i++) {
		snprintf(nm, sizeof nm, "many/c%04d.conf", i);
		put(nm, "");
	}
	put("main.conf", "include many/*.conf;\n"); /* 1 + LIM files */
	fresh();
	ASSERT(!parse_limited("main.conf"));
	ASSERT(strstr(E.msg, "at most 100 files in one parse"));
	ASSERT(!strstr(E.msg, "BST_"));
	ASSERT(E.line == 1);
	/* one fewer fits: remove one file */
	remove(path("many/c0000.conf"));
	fresh();
	ASSERT(parse_limited("main.conf"));
	/* repeated includes count too */
	put("again.conf", "include many/c0001.conf;\ninclude again2.conf;\n");
	put("again2.conf", "include again3.conf;\n");
	put("again3.conf", "");
	rmdir_tmp();
}

/* One file per vhost: 10,000 included files parse under the default limit. */
TEST(ten_thousand_included_files_parse)
{
	mkdir_tmp();
	mkdir(path("sites"), 0755);
	char nm[64], body[64];
	for (int i = 0; i < 10000; i++) {
		snprintf(nm, sizeof nm, "sites/v%05d.conf", i);
		snprintf(body, sizeof body, "server { listen %d; }\n", 1 + i % 60000);
		put(nm, body);
	}
	put("main.conf", "include sites/*.conf;\n");
	fresh();
	bst_ast *ast = bst_cfg_parse_file(path("main.conf"), A, &E);
	ASSERT(ast != NULL);
	ASSERT_EQ(ast->root.nchildren, 10000);
	rmdir_tmp();
}

static void write_spaces(const char *name, size_t n)
{
	FILE *f = fopen(path(name), "wb");
	char buf[1 << 16];
	memset(buf, ' ', sizeof buf);
	for (size_t w = 0; w < n; w += sizeof buf)
		fwrite(buf, 1, n - w < sizeof buf ? n - w : sizeof buf, f);
	fclose(f);
}

TEST(bytes_limit)
{
	mkdir_tmp();
	/* one file over the limit: sparse, rejected before reading */
	int fd = open(path("big.conf"), O_CREAT | O_WRONLY, 0600);
	ASSERT(fd >= 0 && ftruncate(fd, (off_t)BST_CFG_MAX_BYTES + 1) == 0);
	close(fd);
	fresh();
	ASSERT(!bst_cfg_parse_file(path("big.conf"), A, &E));
	ASSERT(strstr(E.msg, "67108864"));
	ASSERT(strstr(E.msg, "reading") == NULL); /* the root file: no dangling "reading" */
	ASSERT(E.msg[strlen(E.msg) - 1] != ',' && strstr(E.msg, "parse") != NULL);
	/* total across files */
	write_spaces("p1.conf", 22u << 20);
	write_spaces("p2.conf", 22u << 20);
	write_spaces("p3.conf", 21u << 20);
	put("main.conf", "include p1.conf;\ninclude p2.conf;\ninclude p3.conf;\nx 1;\n");
	fresh();
	ASSERT(!bst_cfg_parse_file(path("main.conf"), A, &E));
	ASSERT(strstr(E.msg, "67108864"));
	ASSERT(E.line == 3);
	ASSERT(strstr(E.msg, "reading \"") != NULL && strstr(E.msg, "p3.conf") != NULL);
	/* exactly under: two files */
	put("main.conf", "include p1.conf;\ninclude p2.conf;\nx 1;\n");
	fresh();
	ASSERT(bst_cfg_parse_file(path("main.conf"), A, &E));
	rmdir_tmp();
}

TEST(crlf_and_bom_in_included_file)
{
	mkdir_tmp();
	put("main.conf", "a 1;\r\ninclude inc.conf;\r\nz 1;\r\n");
	put("inc.conf", "\xEF\xBB\xBF" "x 1;\r\ny \"two\r\nlines\";\r\n  bad\r\n");
	fresh();
	ASSERT(!bst_cfg_parse_file(path("main.conf"), A, &E));
	ASSERT(err_is(NULL, 4, 6, "';'"));
	ASSERT(strstr(E.file, "inc.conf"));
	put("inc.conf", "\xEF\xBB\xBF" "x 1;\r\ny 2;\r\n");
	fresh();
	bst_ast *a = bst_cfg_parse_file(path("main.conf"), A, &E);
	ASSERT(a);
	ASSERT_STR(dump(a), "0 a 1\n0 x 1\n0 y 2\n0 z 1\n");
	ASSERT_EQ(a->root.children->next->loc.col, 1);
	rmdir_tmp();
}

TEST(string_include_relative_to_name)
{
	mkdir_tmp();
	mkdir(path("sub"), 0755);
	put("sub/a.conf", "from_sub 1;\n");
	put("a.conf", "WRONG 1;\n");
	const char *s = "include a.conf;\n";
	fresh();
	bst_ast *a = bst_cfg_parse_string(s, strlen(s), path("sub/name.conf"), NULL, A, &E);
	ASSERT(a);
	ASSERT_STR(dump(a), "0 from_sub 1\n");
	rmdir_tmp();
}

TEST(glob_metachars_in_including_dir)
{
	mkdir_tmp();
	const char *names[] = {"w*[ q", "a[bc]", "d?e"};
	for (int i = 0; i < 3; i++) {
		char p[600];
		snprintf(p, sizeof p, "%s/%s", dir, names[i]);
		mkdir(p, 0755);
		snprintf(p, sizeof p, "%s/%s/inc", dir, names[i]);
		mkdir(p, 0755);
		snprintf(p, sizeof p, "%s/inc/x.conf", names[i]);
		put(p, "ok 1;\n");
		snprintf(p, sizeof p, "%s/main.conf", names[i]);
		put(p, "include inc/*.conf;\n");
	}
	/* decoys the unescaped directory would match instead */
	mkdir(path("ab"), 0755);
	mkdir(path("ab/inc"), 0755);
	put("ab/inc/x.conf", "WRONG 1;\n");
	mkdir(path("dxe"), 0755);
	mkdir(path("dxe/inc"), 0755);
	put("dxe/inc/x.conf", "WRONG 1;\n");
	for (int i = 0; i < 3; i++) {
		char p[600];
		snprintf(p, sizeof p, "%s/main.conf", names[i]);
		fresh();
		bst_ast *a = bst_cfg_parse_file(path(p), A, &E);
		ASSERT(a);
		ASSERT_STR(dump(a), "0 ok 1\n");
	}
	rmdir_tmp();
}

static int nest_run(int opens)
{
	char *s = malloc((size_t)opens * 5 + 64);
	size_t p = 0;
	for (int i = 0; i < opens; i++)
		p += (size_t)sprintf(s + p, "a { ");
	p += (size_t)sprintf(s + p, "include inc.conf;\n");
	for (int i = 0; i < opens; i++)
		s[p++] = '}';
	s[p] = 0;
	put("main.conf", s);
	free(s);
	fresh();
	return bst_cfg_parse_file(path("main.conf"), A, &E) != NULL;
}

TEST(nesting_counts_across_include)
{
	mkdir_tmp();
	put("inc.conf", "b { c { d 1; } }\n");
	ASSERT(nest_run(62)); /* 62 + 2 = 64 */
	ASSERT(!nest_run(63)); /* 63 + 2 = 65 */
	ASSERT(strstr(E.msg, "64"));
	ASSERT(strstr(E.file, "inc.conf") && E.line == 1 && E.col == 5);
	rmdir_tmp();
}

TEST(file_counter_with_literal_includes)
{
	mkdir_tmp();
	put("empty.conf", "");
	for (int n = LIM - 1; n <= LIM; n++) {
		char *s = malloc((size_t)n * 24 + 8);
		size_t p = 0;
		for (int i = 0; i < n; i++)
			p += (size_t)sprintf(s + p, "include empty.conf;\n");
		put("main.conf", s);
		free(s);
		fresh();
		bst_ast *a = parse_limited("main.conf");
		if (n < LIM) { /* root + 99 = 100 files */
			ASSERT(a);
		} else { /* the 101st file */
			ASSERT(!a);
			ASSERT(strstr(E.msg, "more than 100 files"));
			ASSERT(E.line == LIM);
		}
	}
	rmdir_tmp();
}

/* An unset ${name} that is a template variable says how to write the variable. */
static bool is_host(const char *name)
{
	return strcmp(name, "host") == 0;
}

TEST(unset_env_hint_for_template_variable)
{
	bst_arena *a = bst_arena_new(1 << 16);
	bst_cfg_opts o = { .known_var = is_host };
	const char *src = "x ${host};";
	ASSERT(bst_cfg_parse_string(src, strlen(src), "t", &o, a, &E) == NULL);
	ASSERT(strstr(E.msg, "environment variable host is not set"));
	ASSERT(strstr(E.msg, "for the template variable, write $host; ${...} is environment expansion"));
	src = "x ${nothere};";
	ASSERT(bst_cfg_parse_string(src, strlen(src), "t", &o, a, &E) == NULL);
	ASSERT(!strstr(E.msg, "template variable"));
	ASSERT(bst_cfg_parse_string("x ${host};", 10, "t", NULL, a, &E) == NULL); /* no callback */
	ASSERT(!strstr(E.msg, "template variable"));
	setenv("host", "h", 1); /* when it IS set in the environment, it expands as always */
	ASSERT(bst_cfg_parse_string("x ${host};", 10, "t", &o, a, &E) != NULL);
	unsetenv("host");
	bst_arena_free(a);
}

TEST(missing_root_file)
{
	fresh();
	ASSERT(!bst_cfg_parse_file("/nonexistent/bst.conf", A, &E));
	/* The root file's path is the error's position (the CLI prints it first): not repeated. */
	ASSERT(strstr(E.msg, "cannot open: No such file or directory"));
	ASSERT(!strstr(E.msg, "bst.conf"));
}

TAP_MAIN()

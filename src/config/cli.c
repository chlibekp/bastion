/* See cli.h. */
#include "config/cli.h"

#include "config/compile.h"
#include "config/dump.h"
#include "config/schema.h"

#include <openssl/crypto.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef BST_VERSION
#define BST_VERSION "0.0.0"
#endif

static const char usage_text[] =
	"usage: bastion [-c file] [-t] [-T]\n"
	"       bastion serve <dir> [--port n]\n"
	"       bastion proxy <url> [--port n]\n"
	"       bastion --dump-schema | --help | --version\n"
	"\n"
	"  -c file        configuration file (default " BST_DEFAULT_CONFIG ")\n"
	"  -t             check the configuration and exit\n"
	"  -T             check, then print the effective configuration and exit.\n"
	"                 It prints environment-expanded values, so it can show secrets:\n"
	"                 do not paste it into a bug report unreviewed.\n"
	"  serve, proxy   run without a config file (default port 8080)\n"
	"  --dump-schema  print every directive as JSON\n"
	"\n"
	"exit status: 0 ok, 1 configuration error, 2 usage error\n";

/* Writes s with control bytes escaped, so untrusted text cannot move the cursor. */
static void put_escaped(FILE *f, const char *s)
{
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c < 0x20 || c == 0x7f)
			fprintf(f, "\\x%02x", c);
		else
			fputc(c, f);
	}
}

typedef struct opts {
	const char *conf;
	const char *verb; /* "serve", "proxy" or NULL */
	const char *target;
	uint16_t port;
	bool t, T, help, version, dump_schema;
} opts;

/* One line: bastion: <pre><arg><post>; try 'bastion --help'. arg is user text, shown
 * escaped and cut to 40 bytes. */
static int usage_err(const char *pre, const char *arg, const char *post)
{
	char shown[48];
	size_t n = 0;
	for (; arg[n] && n < 40; n++)
		shown[n] = (unsigned char)arg[n] < 0x20 || arg[n] == 0x7f ? '?' : arg[n];
	shown[n] = 0;
	fprintf(stderr, "bastion: %s%s%s; try 'bastion --help'\n", pre, shown, post);
	return 2;
}

static bool parse_port(const char *s, uint16_t *out)
{
	size_t n = strlen(s);
	if (n == 0 || n > 5 || (n > 1 && s[0] == '0')) /* no leading zeros, as in `listen` */
		return false;
	unsigned v = 0;
	for (size_t i = 0; i < n; i++) {
		if (s[i] < '0' || s[i] > '9')
			return false;
		v = v * 10 + (unsigned)(s[i] - '0');
	}
	if (v < 1 || v > 65535)
		return false;
	*out = (uint16_t)v;
	return true;
}

/* 0, or the exit status (2) after printing the usage error. */
static int parse_opts(int argc, char **argv, opts *o)
{
	memset(o, 0, sizeof *o);
	o->port = BST_QUICK_PORT;
	int i = 1;
	if (argc > 1 && (strcmp(argv[1], "serve") == 0 || strcmp(argv[1], "proxy") == 0)) {
		o->verb = argv[1];
		if (argc < 3 || argv[2][0] == '-')
			return usage_err("", o->verb, " needs an argument");
		o->target = argv[2];
		i = 3;
	}
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (strcmp(a, "-t") == 0) {
			o->t = true;
		} else if (strcmp(a, "-T") == 0) {
			o->T = true;
		} else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
			o->help = true;
		} else if (strcmp(a, "--version") == 0) {
			o->version = true;
		} else if (strcmp(a, "--dump-schema") == 0) {
			o->dump_schema = true;
		} else if (strcmp(a, "-c") == 0 || strcmp(a, "--port") == 0) {
			bool is_c = a[1] == 'c';
			if (is_c == (o->verb != NULL))
				return is_c ? usage_err("-c cannot be used with ", o->verb, "")
					    : usage_err("", a, " needs serve or proxy");
			if (i + 1 >= argc)
				return usage_err("", a, " needs a value");
			i++;
			if (is_c)
				o->conf = argv[i];
			else if (!parse_port(argv[i], &o->port))
				return usage_err("invalid port ", argv[i], " (want 1-65535)");
		} else if (a[0] == '-') {
			return usage_err("unknown option ", a, "");
		} else {
			return usage_err("unexpected argument ", a, "");
		}
	}
	return 0;
}

bst_ast *bst_cli_build_ast(const char *verb, const char *arg, uint16_t port, bst_arena *a,
			   bst_err *e)
{
	bst_loc loc = { .file = verb, .line = 1, .col = 1 };
	bst_ast *ast = bst_arena_alloc(a, sizeof *ast);
	bst_ast_node *srv = bst_arena_alloc(a, sizeof *srv);
	bst_ast_node *kids = bst_arena_alloc(a, 2 * sizeof *kids);
	bst_ast_arg *args = bst_arena_alloc(a, 2 * sizeof *args);
	char *ptxt = bst_arena_alloc(a, 8);
	if (!ast || !srv || !kids || !args || !ptxt) {
		bst_err_set(e, "out of memory");
		return NULL;
	}
	memset(ast, 0, sizeof *ast);
	memset(srv, 0, sizeof *srv);
	memset(kids, 0, 2 * sizeof *kids);
	snprintf(ptxt, 8, "%u", (unsigned)port);
	size_t alen = strlen(arg);
	/* The target is STRING_RAW: its tpl has every `$` doubled, so it is never a template. */
	size_t dollars = 0;
	for (size_t i = 0; i < alen; i++)
		dollars += arg[i] == '$';
	char *tpl = bst_arena_alloc(a, alen + dollars + 1);
	char *txt = bst_arena_alloc(a, alen + 1);
	if (!tpl || !txt) {
		bst_err_set(e, "out of memory");
		return NULL;
	}
	memcpy(txt, arg, alen + 1);
	size_t k = 0;
	for (size_t i = 0; i < alen; i++) {
		tpl[k++] = arg[i];
		if (arg[i] == '$')
			tpl[k++] = '$';
	}
	tpl[k] = 0;
	args[0] = (bst_ast_arg){ BST_TOK_WORD, ptxt, strlen(ptxt), ptxt, strlen(ptxt), loc };
	args[1] = (bst_ast_arg){ BST_TOK_STRING_RAW, txt, alen, tpl, k, loc };
	const char *dname = strcmp(verb, "serve") == 0 ? "root" : "proxy";
	kids[0] = (bst_ast_node){ .name = "listen", .name_len = 6, .args = &args[0], .nargs = 1,
				  .parent = srv, .next = &kids[1], .loc = loc };
	kids[1] = (bst_ast_node){ .name = dname, .name_len = strlen(dname), .args = &args[1],
				  .nargs = 1, .parent = srv, .loc = loc };
	*srv = (bst_ast_node){ .name = "server", .name_len = 6, .has_block = 1, .children = &kids[0],
			       .nchildren = 2, .parent = &ast->root, .tail = &kids[1], .loc = loc };
	ast->root.children = srv;
	ast->root.nchildren = 1;
	ast->root.tail = srv;
	return ast;
}

static int config_error(const bst_err *e)
{
	if (e->file != NULL) {
		put_escaped(stderr, e->file);
		if (e->line > 0)
			fprintf(stderr, ":%d:%d: ", e->line, e->col);
		else
			fputs(": ", stderr); /* no position, such as a file that cannot be opened */
	} else {
		fputs("bastion: ", stderr);
	}
	put_escaped(stderr, e->msg);
	fputc('\n', stderr);
	return 1;
}

/* Load-time warnings, one line each: file:line:col: warning: message. They never change the
 * exit status. */
static void print_warnings(const bst_config *cfg)
{
	size_t n;
	const bst_cfg_warning *w = bst_config_warnings(cfg, &n);
	for (size_t i = 0; i < n; i++) {
		if (w[i].file != NULL) {
			put_escaped(stderr, w[i].file);
			fprintf(stderr, ":%d:%d: ", w[i].line, w[i].col);
		} else {
			fputs("bastion: ", stderr);
		}
		fputs("warning: ", stderr);
		put_escaped(stderr, w[i].msg);
		fputc('\n', stderr);
	}
}

int bst_cli_main(int argc, char **argv)
{
	opts o;
	int rc = parse_opts(argc, argv, &o);
	if (rc != 0)
		return rc;
	bst_err e = { .msg = "" };
	if (o.help) {
		fputs(usage_text, stdout);
		return 0;
	}
	if (o.version) {
		printf("bastion %s (%s)\n", BST_VERSION, OpenSSL_version(OPENSSL_VERSION));
		return 0;
	}
	if (o.dump_schema) {
		const bst_schema *s = bst_schema_registry(&e);
		return s && bst_schema_dump_json(s, stdout, &e) == 0 ? 0 : config_error(&e);
	}

	bst_arena *arena = bst_arena_new((size_t)64 << 10);
	if (arena == NULL) {
		bst_err_set(&e, "out of memory");
		return config_error(&e);
	}
	bst_ast *ast;
	if (o.verb != NULL) {
		ast = bst_cli_build_ast(o.verb, o.target, o.port, arena, &e);
	} else {
		const char *path = o.conf ? o.conf : BST_DEFAULT_CONFIG;
		if (o.conf == NULL && access(path, R_OK) != 0) {
			bst_err_set(&e, "cannot read the default configuration %s (use -c file)", path);
			ast = NULL;
		} else {
			ast = bst_cfg_parse_file(path, arena, &e);
		}
		if (ast == NULL && e.file == NULL)
			e.file = path; /* errors without a position still start with the path */
	}
	bst_config *cfg = ast ? bst_cfg_compile(ast, &e) : NULL;
	if (cfg == NULL) {
		rc = config_error(&e);
	} else if (o.T) {
		print_warnings(cfg);
		const bst_schema *s = bst_schema_registry(&e);
		rc = s && bst_cfg_dump(s, ast, stdout, &e) == 0 ? 0 : config_error(&e);
	} else if (o.t) {
		print_warnings(cfg);
		puts("configuration ok");
		rc = 0;
	} else {
		/* Phase 3 replaces this branch with the server runtime (master, workers, listeners). */
		fputs("server runtime not available yet\n", stderr);
		rc = 2;
	}
	bst_config_free(cfg);
	bst_arena_free(arena);
	return rc;
}

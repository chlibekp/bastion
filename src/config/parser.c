/* Config parser, see parser.h for the contract. */
#include "config/parser.h"

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct sbuf {
	char *p;
	size_t len, cap;
} sbuf;

typedef struct file_id {
	dev_t dev;
	ino_t ino;
	const char *path; /* arena string */
} file_id;

typedef struct pctx {
	bst_arena *a;
	bst_err *err;
	int no_include;
	size_t files, bytes, expanded;
	int depth; /* include nesting of the unit being parsed; root is 0 */
	file_id chain[BST_CFG_MAX_INCLUDE_DEPTH + 1];
	int nchain;
	bst_ast_arg args[BST_CFG_MAX_ARGS]; /* statement under construction */
	sbuf txt, tpl;
} pctx;

/* ---- errors ---- */

/* Bytes that must not reach logs raw become \xHH. Returns out. */
static char *esc(const char *s, char *out, size_t cap)
{
	size_t n = 0;
	for (; *s && n + 5 < cap; s++) {
		unsigned char c = (unsigned char)*s;
		if (c < 0x20 || c == 0x7f || c == '\\' || c == '"') {
			n += (size_t)snprintf(out + n, cap - n, "\\x%02x", c);
		} else {
			out[n++] = (char)c;
		}
	}
	out[n] = 0;
	return out;
}

/* file must be arena-owned (or NULL). Always returns -1. */
static int fail(pctx *c, const char *file, int line, int col, const char *fmt, ...)
	__attribute__((format(printf, 5, 6)));
static int fail(pctx *c, const char *file, int line, int col, const char *fmt, ...)
{
	char buf[sizeof c->err->msg];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	if (c->err) {
		bst_err_set(c->err, "%s", buf);
		c->err->file = file;
		c->err->line = line;
		c->err->col = col;
	}
	return -1;
}

static int fail_loc(pctx *c, bst_loc l, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
static int fail_loc(pctx *c, bst_loc l, const char *fmt, ...)
{
	char buf[sizeof c->err->msg];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	return fail(c, l.file, l.line, l.col, "%s", buf);
}

static int fail_oom(pctx *c)
{
	return fail(c, NULL, 0, 0, "out of memory");
}

static char *arena_dup(pctx *c, const char *s, size_t n)
{
	char *p = bst_arena_alloc(c->a, n + 1);
	if (!p)
		return NULL;
	memcpy(p, s, n);
	p[n] = 0;
	return p;
}

/* ---- AST ---- */

const bst_ast_node *bst_ast_next(const bst_ast *ast, const bst_ast_node *n)
{
	if (!n)
		return ast->root.children;
	if (n->children)
		return n->children;
	while (!n->next) {
		n = n->parent;
		if (n == &ast->root)
			return NULL;
	}
	return n->next;
}

/* ---- environment expansion ---- */

static int sb_put(sbuf *b, const char *s, size_t n)
{
	if (n == 0)
		return 0;
	if (n > BST_CFG_MAX_ARG_BYTES || b->len > BST_CFG_MAX_ARG_BYTES - n)
		return -2;
	if (b->len + n > b->cap) {
		size_t cap = b->cap ? b->cap : 256;
		while (cap < b->len + n)
			cap *= 2;
		char *p = realloc(b->p, cap);
		if (!p)
			return -1;
		b->p = p;
		b->cap = cap;
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
	return 0;
}

/* Append literal env/default text: as is to txt, `$` doubled to tpl. */
static int put_literal(pctx *c, const char *s, size_t n)
{
	int r = sb_put(&c->txt, s, n);
	for (size_t i = 0; r == 0 && i < n;) {
		size_t j = i;
		while (j < n && s[j] != '$')
			j++;
		r = sb_put(&c->tpl, s + i, j - i);
		if (r == 0 && j < n)
			r = sb_put(&c->tpl, "$$", 2);
		i = j + 1;
	}
	return r;
}

static int name_len(const char *s, size_t n)
{
	size_t i = 0;
	while (i < n && ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') ||
			 s[i] == '_' || (i > 0 && s[i] >= '0' && s[i] <= '9')))
		i++;
	return (int)i;
}

/* Builds the arg's text and tpl from token t. */
static int expand_arg(pctx *c, const bst_token *t, bst_ast_arg *out)
{
	bst_loc loc = {t->file, t->line, t->col};
	const char *s = t->text;
	size_t n = t->len;
	c->txt.len = c->tpl.len = 0;
	int r = 0;
	for (size_t i = 0; r == 0 && i < n;) {
		if (t->kind == BST_TOK_STRING_RAW) {
			r = put_literal(c, s + i, n - i);
			break;
		}
		if (s[i] != '$' || i + 1 >= n || s[i + 1] != '{') {
			size_t j = i + 1;
			while (j < n && !(s[j] == '$' && j + 1 < n && s[j + 1] == '{'))
				j++;
			r = sb_put(&c->txt, s + i, j - i);
			if (r == 0)
				r = sb_put(&c->tpl, s + i, j - i);
			i = j;
			continue;
		}
		const char *in = s + i + 2;
		const char *close = memchr(in, '}', n - i - 2);
		if (!close)
			return fail_loc(c, loc, "unterminated ${ in argument");
		size_t inner = (size_t)(close - in);
		int nl = name_len(in, inner);
		if (nl == 0 || (size_t)nl > 255)
			return fail_loc(c, loc,
					"invalid environment variable name in ${...}: must match "
					"[A-Za-z_][A-Za-z0-9_]*, at most 255 bytes");
		const char *rest = in + nl;
		size_t rlen = inner - (size_t)nl;
		int has_def = 0;
		if (rlen >= 2 && rest[0] == ':' && rest[1] == '-') {
			has_def = 1;
			rest += 2;
			rlen -= 2;
		} else if (rlen != 0) {
			return fail_loc(c, loc, "invalid ${...} syntax: expected ${NAME} or "
						"${NAME:-default}");
		}
		char name[256];
		memcpy(name, in, (size_t)nl);
		name[nl] = 0;
		const char *v = getenv(name);
		if (v) {
			r = put_literal(c, v, strlen(v));
		} else if (has_def) {
			r = put_literal(c, rest, rlen);
		} else {
			return fail_loc(c, loc, "environment variable %s is not set", name);
		}
		i = (size_t)(close - s) + 1;
	}
	if (r == -1)
		return fail_oom(c);
	if (r == -2)
		return fail_loc(c, loc, "argument longer than %zu bytes after expansion "
					"(BST_CFG_MAX_ARG_BYTES)",
				(size_t)BST_CFG_MAX_ARG_BYTES);
	if (c->txt.len > BST_CFG_MAX_EXPANDED - c->expanded)
		return fail_loc(c, loc, "expanded arguments exceed %zu bytes per parse "
					"(BST_CFG_MAX_EXPANDED)",
				(size_t)BST_CFG_MAX_EXPANDED);
	c->expanded += c->txt.len;
	out->kind = t->kind;
	out->loc = loc;
	out->len = c->txt.len;
	out->text = arena_dup(c, c->txt.p ? c->txt.p : "", c->txt.len);
	if (!out->text)
		return fail_oom(c);
	out->tpl_len = c->tpl.len;
	out->tpl = c->tpl.len == c->txt.len ? out->text
					    : arena_dup(c, c->tpl.p, c->tpl.len);
	return out->tpl ? 0 : fail_oom(c);
}

/* ---- file loading ---- */

static int read_file(pctx *c, int fd, size_t hint, bst_loc at, const char *shown, char **out,
		     size_t *outn)
{
	size_t budget = BST_CFG_MAX_BYTES - c->bytes;
	size_t cap = hint < budget ? hint + 1 : budget + 1;
	char *buf = malloc(cap);
	size_t n = 0;
	if (!buf)
		return fail_oom(c);
	for (;;) {
		if (n == cap) {
			if (cap > budget) {
				free(buf);
				return fail_loc(c, at, "config files exceed %zu bytes per parse "
						       "(BST_CFG_MAX_BYTES), reading \"%s\"",
						(size_t)BST_CFG_MAX_BYTES, shown);
			}
			cap = cap > budget / 2 ? budget + 1 : cap * 2;
			char *p = realloc(buf, cap);
			if (!p) {
				free(buf);
				return fail_oom(c);
			}
			buf = p;
		}
		ssize_t r = read(fd, buf + n, cap - n);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			int e = errno;
			free(buf);
			return fail_loc(c, at, "cannot read \"%s\": %s", shown, strerror(e));
		}
		if (r == 0)
			break;
		n += (size_t)r;
		if (n > budget) {
			free(buf);
			return fail_loc(c, at, "config files exceed %zu bytes per parse "
					       "(BST_CFG_MAX_BYTES), reading \"%s\"",
					(size_t)BST_CFG_MAX_BYTES, shown);
		}
	}
	c->bytes += n;
	*out = buf;
	*outn = n;
	return 0;
}

static int parse_unit(pctx *c, bst_ast_node *parent, int nest_base, const char *text,
		      size_t len, const char *file);

/* Opens, checks and parses one file into parent. at.file is NULL for the root file. */
static int load_file(pctx *c, bst_ast_node *parent, int nest_base, const char *path,
		     bst_loc at)
{
	char sh[300], sh2[300];
	esc(path, sh, sizeof sh);
	if (c->depth + 1 > BST_CFG_MAX_INCLUDE_DEPTH)
		return fail_loc(c, at, "include depth exceeds %d (BST_CFG_MAX_INCLUDE_DEPTH) at \"%s\"",
				BST_CFG_MAX_INCLUDE_DEPTH, sh);
	if (c->files >= BST_CFG_MAX_FILES)
		return fail_loc(c, at, "more than %d files in one parse "
				       "(BST_CFG_MAX_FILES), at \"%s\"",
				BST_CFG_MAX_FILES, sh);
	c->files++;
	int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
	if (fd < 0)
		return fail_loc(c, at, "cannot open \"%s\": %s", sh, strerror(errno));
	struct stat st;
	if (fstat(fd, &st) < 0) {
		int e = errno;
		close(fd);
		return fail_loc(c, at, "cannot stat \"%s\": %s", sh, strerror(e));
	}
	if (!S_ISREG(st.st_mode)) {
		close(fd);
		return fail_loc(c, at, "\"%s\" is not a regular file", sh);
	}
	const char *name = arena_dup(c, path, strlen(path));
	if (!name) {
		close(fd);
		return fail_oom(c);
	}
	for (int i = 0; i < c->nchain; i++) {
		if (c->chain[i].dev != st.st_dev || c->chain[i].ino != st.st_ino)
			continue;
		char msg[sizeof c->err->msg];
		size_t n = (size_t)snprintf(msg, sizeof msg, "include cycle: ");
		for (int j = i; j <= c->nchain && n < sizeof msg; j++) {
			const char *p = j < c->nchain ? c->chain[j].path : name;
			n += (size_t)snprintf(msg + n, sizeof msg - n, "%s%s", j > i ? " -> " : "",
					      esc(p, sh2, sizeof sh2));
		}
		close(fd);
		return fail_loc(c, at, "%s", msg);
	}
	if ((size_t)st.st_size > BST_CFG_MAX_BYTES - c->bytes) {
		close(fd);
		return fail_loc(c, at, "config files exceed %zu bytes per parse "
				       "(BST_CFG_MAX_BYTES), reading \"%s\"",
				(size_t)BST_CFG_MAX_BYTES, sh);
	}
	char *text;
	size_t n;
	int r = read_file(c, fd, (size_t)st.st_size, at, sh, &text, &n);
	close(fd);
	if (r < 0)
		return -1;
	c->chain[c->nchain].dev = st.st_dev;
	c->chain[c->nchain].ino = st.st_ino;
	c->chain[c->nchain].path = name;
	c->nchain++;
	c->depth++;
	r = parse_unit(c, parent, nest_base, text, n, name);
	c->depth--;
	c->nchain--;
	free(text);
	return r;
}

static int cmp_str(const void *x, const void *y)
{
	return strcmp(*(char *const *)x, *(char *const *)y);
}

/* A missing directory is "no match" (as in nginx); other read errors abort the glob (errfunc, not GLOB_ERR: that flag aborts even when errfunc says continue). */
static int glob_err(const char *p, int e)
{
	(void)p;
	return !(e == ENOENT || e == ENOTDIR);
}

/* Appends s to out with glob metacharacters escaped. */
static size_t glob_escape(const char *s, size_t n, char *out)
{
	size_t k = 0;
	for (size_t i = 0; i < n; i++) {
		if (strchr("*?[\\", s[i]))
			out[k++] = '\\';
		out[k++] = s[i];
	}
	return k;
}

static int include_pattern(pctx *c, bst_ast_node *parent, int nest, const char *includer,
			   const bst_ast_arg *arg)
{
	const char *pat = arg->text;
	if (arg->len == 0)
		return fail_loc(c, arg->loc, "include path is empty");
	if (strlen(pat) != arg->len)
		return fail_loc(c, arg->loc, "include path contains a NUL byte");
	/* directory of the including file (for string input, of its name), with the trailing
	 * '/', or "" for the current directory */
	size_t dlen = 0;
	if (pat[0] != '/') {
		const char *sl = strrchr(includer, '/');
		dlen = sl ? (size_t)(sl - includer) + 1 : 0;
	}
	size_t plen = arg->len;
	char *lit = malloc(dlen + plen + 1);
	char *gp = malloc(dlen * 2 + plen + 1);
	if (!lit || !gp) {
		free(lit);
		free(gp);
		return fail_oom(c);
	}
	memcpy(lit, includer, dlen);
	size_t gl = glob_escape(includer, dlen, gp);
	memcpy(lit + dlen, pat, plen + 1);
	memcpy(gp + gl, pat, plen + 1);

	int rc;
	if (!strpbrk(pat, "*?[")) {
		rc = load_file(c, parent, nest, lit, arg->loc);
	} else {
		glob_t g;
		memset(&g, 0, sizeof g);
		int gr = glob(gp, GLOB_NOSORT, glob_err, &g);
		char sh[300];
		if (gr == GLOB_NOMATCH) {
			rc = 0;
		} else if (gr != 0) {
			rc = fail_loc(c, arg->loc, "cannot expand \"%s\": %s",
				      esc(pat, sh, sizeof sh),
				      gr == GLOB_NOSPACE ? "out of memory" : "read error");
		} else if (g.gl_pathc > BST_CFG_MAX_FILES - c->files) {
			rc = fail_loc(c, arg->loc,
				      "\"%s\" matches %zu files; at most %d files per parse "
				      "(BST_CFG_MAX_FILES)",
				      esc(pat, sh, sizeof sh), (size_t)g.gl_pathc,
				      BST_CFG_MAX_FILES);
		} else {
			/* bytewise order, independent of locale */
			qsort(g.gl_pathv, g.gl_pathc, sizeof *g.gl_pathv, cmp_str);
			rc = 0;
			for (size_t i = 0; rc == 0 && i < g.gl_pathc; i++)
				rc = load_file(c, parent, nest, g.gl_pathv[i], arg->loc);
		}
		globfree(&g);
	}
	free(lit);
	free(gp);
	return rc;
}

/* ---- parser ---- */

static int make_node(pctx *c, bst_ast_node *parent, const bst_token *name, size_t nargs,
		     int block, bst_ast_node **out)
{
	bst_ast_node *nd = bst_arena_alloc(c->a, sizeof *nd);
	if (!nd)
		return fail_oom(c);
	memset(nd, 0, sizeof *nd);
	nd->name = arena_dup(c, name->text, name->len);
	nd->name_len = name->len;
	if (nargs) {
		nd->args = bst_arena_alloc(c->a, nargs * sizeof *nd->args);
		if (!nd->args)
			return fail_oom(c);
		memcpy(nd->args, c->args, nargs * sizeof *nd->args);
	}
	if (!nd->name)
		return fail_oom(c);
	nd->nargs = nargs;
	nd->has_block = block;
	nd->parent = parent;
	nd->loc = (bst_loc){name->file, name->line, name->col};
	if (parent->tail)
		parent->tail->next = nd;
	else
		parent->children = nd;
	parent->tail = nd;
	parent->nchildren++;
	*out = nd;
	return 0;
}

static int parse_unit(pctx *c, bst_ast_node *parent, int nest_base, const char *text,
		      size_t len, const char *file)
{
	bst_lexer lx;
	bst_lexer_init(&lx, c->a, text, len, file);
	bst_ast_node *stack[BST_CFG_MAX_NESTING];
	int sp = 0;
	for (;;) {
		bst_ast_node *cur = sp ? stack[sp - 1] : parent;
		bst_token t = bst_lexer_next(&lx);
		bst_loc tl = {t.file, t.line, t.col};
		switch (t.kind) {
		case BST_TOK_ERROR:
			return fail_loc(c, tl, "%s", t.msg);
		case BST_TOK_EOF:
			if (sp)
				return fail_loc(c, stack[sp - 1]->loc,
						"unclosed block: missing '}' before end of file");
			return 0;
		case BST_TOK_RBRACE:
			if (!sp)
				return fail_loc(c, tl, "unexpected '}' with no open block");
			sp--;
			continue;
		case BST_TOK_SEMI:
			return fail_loc(c, tl, "empty statement: ';' without a directive");
		case BST_TOK_LBRACE:
			return fail_loc(c, tl, "block without a directive name");
		case BST_TOK_STRING_TPL:
		case BST_TOK_STRING_RAW:
			return fail_loc(c, tl, "directive name must be a bare word, not a "
					       "quoted string");
		case BST_TOK_WORD:
			break;
		}
		bst_token name = t;
		size_t nargs = 0;
		bst_loc last = tl; /* where ';' was expected: just after the last token */
		bst_token end;
		for (;;) {
			end = bst_lexer_next(&lx);
			if (end.kind == BST_TOK_WORD || end.kind == BST_TOK_STRING_TPL ||
			    end.kind == BST_TOK_STRING_RAW) {
				if (nargs == BST_CFG_MAX_ARGS)
					return fail(c, end.file, end.line, end.col,
						    "more than %d arguments in one statement "
						    "(BST_CFG_MAX_ARGS)",
						    BST_CFG_MAX_ARGS);
				if (expand_arg(c, &end, &c->args[nargs]) < 0)
					return -1;
				nargs++;
				last = (bst_loc){end.file, end.line, end.col};
				if (end.kind == BST_TOK_WORD)
					last.col += (int)end.len;
				continue;
			}
			break;
		}
		if (end.kind == BST_TOK_ERROR)
			return fail(c, end.file, end.line, end.col, "%s", end.msg);
		if (end.kind != BST_TOK_SEMI && end.kind != BST_TOK_LBRACE) {
			if (nargs == 0)
				last.col += (int)name.len;
			return fail_loc(c, last, "missing ';' after statement");
		}
		int block = end.kind == BST_TOK_LBRACE;
		if (name.len == 7 && memcmp(name.text, "include", 7) == 0) {
			if (block)
				return fail(c, end.file, end.line, end.col,
					    "include does not take a block");
			if (c->no_include)
				return fail(c, name.file, name.line, name.col,
					    "include is disabled for this input");
			if (nargs == 0)
				return fail(c, name.file, name.line, name.col,
					    "include needs a path argument");
			if (nargs > 1)
				return fail_loc(c, c->args[1].loc,
						"include takes exactly one path");
			bst_ast_arg a1 = c->args[0];
			if (include_pattern(c, cur, nest_base + sp, file, &a1) < 0)
				return -1;
			continue;
		}
		if (block && nest_base + sp >= BST_CFG_MAX_NESTING)
			return fail(c, name.file, name.line, name.col,
				    "blocks nested deeper than %d (BST_CFG_MAX_NESTING)",
				    BST_CFG_MAX_NESTING);
		bst_ast_node *nd;
		if (make_node(c, cur, &name, nargs, block, &nd) < 0)
			return -1;
		if (block)
			stack[sp++] = nd;
	}
}

static bst_ast *finish(pctx *c, bst_ast *ast, int rc)
{
	free(c->txt.p);
	free(c->tpl.p);
	free(c);
	return rc < 0 ? NULL : ast;
}

static pctx *new_ctx(bst_arena *a, bst_err *err, bst_ast **ast)
{
	pctx *c = calloc(1, sizeof *c);
	*ast = bst_arena_alloc(a, sizeof **ast);
	if (!c || !*ast) {
		free(c);
		if (err)
			bst_err_set(err, "out of memory");
		return NULL;
	}
	memset(*ast, 0, sizeof **ast);
	c->a = a;
	c->err = err;
	return c;
}

bst_ast *bst_cfg_parse_string(const char *text, size_t len, const char *name,
			      const bst_cfg_opts *opts, bst_arena *a, bst_err *err)
{
	bst_ast *ast;
	pctx *c = new_ctx(a, err, &ast);
	if (!c)
		return NULL;
	if (opts) {
		c->no_include = opts->no_include;
	}
	const char *nm = arena_dup(c, name ? name : "(string)", strlen(name ? name : "(string)"));
	if (!nm) {
		fail_oom(c);
		return finish(c, ast, -1);
	}
	return finish(c, ast, parse_unit(c, &ast->root, 0, text, len, nm));
}

bst_ast *bst_cfg_parse_file(const char *path, bst_arena *a, bst_err *err)
{
	bst_ast *ast;
	pctx *c = new_ctx(a, err, &ast);
	if (!c)
		return NULL;
	c->depth = -1; /* the root file is include depth 0 */
	bst_loc none = {NULL, 0, 0};
	return finish(c, ast, load_file(c, &ast->root, 0, path, none));
}

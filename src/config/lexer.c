#include "config/lexer.h"

#include <limits.h>

void bst_lexer_init(bst_lexer *l, bst_arena *arena, const char *text, size_t len,
		    const char *file)
{
	*l = (bst_lexer){ .s = text, .len = len, .file = file, .arena = arena, .line = 1, .col = 1 };
	if (len >= 3 && (unsigned char)text[0] == 0xEF && (unsigned char)text[1] == 0xBB &&
	    (unsigned char)text[2] == 0xBF)
		l->pos = 3;
}

static void adv(bst_lexer *l)
{
	if (l->s[l->pos] == '\n') {
		if (l->line < INT_MAX)
			l->line++;
		l->col = 1;
	} else if (l->col < INT_MAX) {
		l->col++;
	}
	l->pos++;
}

static bst_token mk(const bst_lexer *l, bst_tok_kind k, int line, int col)
{
	return (bst_token){ .kind = k, .file = l->file, .line = line, .col = col };
}

static bst_token fail(bst_lexer *l, int line, int col, const char *msg)
{
	bst_token t = mk(l, BST_TOK_ERROR, line, col);
	t.msg = msg;
	l->failed = t;
	l->done = 1;
	return t;
}

static int is_ws(char c)
{
	return c == ' ' || c == '\t' || c == '\n';
}

static int is_delim(char c)
{
	return is_ws(c) || c == ';' || c == '{' || c == '}' || c == '"' || c == '\'' || c == '\r' ||
	       c == '\0';
}

/* Skips whitespace and comments. Returns an ERROR token for a lone CR or NUL, else EOF
 * kind with a sentinel meaning "found a token start" via l->pos < l->len. */
static int skip(bst_lexer *l, bst_token *err)
{
	while (l->pos < l->len) {
		char c = l->s[l->pos];
		if (c == '\r') {
			if (l->pos + 1 < l->len && l->s[l->pos + 1] == '\n') {
				adv(l);
				continue;
			}
			*err = fail(l, l->line, l->col, "stray carriage return");
			return -1;
		}
		if (c == '\0') {
			*err = fail(l, l->line, l->col, "NUL byte in config");
			return -1;
		}
		if (is_ws(c)) {
			adv(l);
		} else if (c == '#') {
			while (l->pos < l->len && l->s[l->pos] != '\n') {
				if (l->s[l->pos] == '\0') {
					*err = fail(l, l->line, l->col, "NUL byte in config");
					return -1;
				}
				adv(l);
			}
		} else {
			break;
		}
	}
	return 0;
}

static bst_token word(bst_lexer *l)
{
	int line = l->line, col = l->col;
	size_t start = l->pos;
	while (l->pos < l->len) {
		char c = l->s[l->pos];
		if (c == '$' && l->pos + 1 < l->len && l->s[l->pos + 1] == '{') {
			int eline = l->line, ecol = l->col;
			adv(l);
			adv(l);
			for (;;) {
				if (l->pos >= l->len || is_ws(l->s[l->pos]) || l->s[l->pos] == '\r' ||
				    l->s[l->pos] == '\0')
					return fail(l, eline, ecol, "unterminated ${");
				if (l->s[l->pos] == '}') {
					adv(l);
					break;
				}
				adv(l);
				if (l->pos - start > BST_LEX_MAX_TOKEN)
					return fail(l, line, col, "token too long");
			}
			continue;
		}
		if (is_delim(c)) {
			if (c == '"' || c == '\'')
				return fail(l, l->line, l->col, "quote inside bare word; quote the whole word, e.g. \"path=/a b\"");
			if (c == '\r' && !(l->pos + 1 < l->len && l->s[l->pos + 1] == '\n'))
				return fail(l, l->line, l->col, "stray carriage return");
			if (c == '\0')
				return fail(l, l->line, l->col, "NUL byte in config");
			break;
		}
		if ((unsigned char)c == 0xEF && l->pos + 2 < l->len &&
		    (unsigned char)l->s[l->pos + 1] == 0xBB && (unsigned char)l->s[l->pos + 2] == 0xBF)
			return fail(l, l->line, l->col, "unexpected byte order mark");
		adv(l);
		if (l->pos - start > BST_LEX_MAX_TOKEN)
			return fail(l, line, col, "token too long");
	}
	if (l->pos - start > BST_LEX_MAX_TOKEN)
		return fail(l, line, col, "token too long");
	bst_token t = mk(l, BST_TOK_WORD, line, col);
	t.text = l->s + start;
	t.len = l->pos - start;
	return t;
}

#ifdef BST_TEST
int bst_lex_test_fail_alloc;
#endif

static void *alloc(bst_lexer *l, size_t n)
{
#ifdef BST_TEST
	if (bst_lex_test_fail_alloc)
		return NULL;
#endif
	return bst_arena_alloc(l->arena, n);
}

static bst_token quoted(bst_lexer *l)
{
	int line = l->line, col = l->col;
	char q = l->s[l->pos];
	int dq = q == '"';
	adv(l);
	size_t start = l->pos, decoded = 0;
	for (;;) {
		if (l->pos >= l->len)
			return fail(l, line, col, "unterminated string");
		char c = l->s[l->pos];
		if (c == q)
			break;
		if (c == '\0')
			return fail(l, l->line, l->col, "NUL byte in config");
		if (dq && c == '\\') {
			adv(l);
			if (l->pos >= l->len)
				return fail(l, line, col, "unterminated string");
			char e = l->s[l->pos];
			if (e == '\0')
				return fail(l, l->line, l->col, "NUL byte in config");
			/* Unrecognised escapes keep both bytes (nginx), so "\.php" works. */
			if (e != 'n' && e != 't' && e != 'r' && e != '"' && e != '\\')
				decoded++;
		}
		adv(l);
		decoded++;
		if (l->pos - start > BST_LEX_MAX_TOKEN)
			return fail(l, line, col, "token too long");
	}
	size_t end = l->pos;
	adv(l);
	if (l->pos < l->len) {
		char n = l->s[l->pos];
		if (!is_ws(n) && n != '\r' && n != ';' && n != '{' && n != '}')
			return fail(l, l->line, l->col, "unexpected character after closing quote");
	}
	bst_token t = mk(l, dq ? BST_TOK_STRING_TPL : BST_TOK_STRING_RAW, line, col);
	if (!dq) {
		t.text = l->s + start;
		t.len = end - start;
		return t;
	}
	char *out = alloc(l, decoded + 1);
	if (out == NULL)
		return fail(l, line, col, "out of memory");
	size_t n = 0;
	for (size_t i = start; i < end; i++) {
		char c = l->s[i];
		if (c == '\\') {
			c = l->s[++i];
			if (c == 'n')
				c = '\n';
			else if (c == 't')
				c = '\t';
			else if (c == 'r')
				c = '\r';
			else if (c != '"' && c != '\\')
				out[n++] = '\\';
		}
		out[n++] = c;
	}
	out[n] = '\0';
	t.text = out;
	t.len = n;
	return t;
}

bst_token bst_lexer_next(bst_lexer *l)
{
	if (l->failed.kind == BST_TOK_ERROR)
		return l->failed;
	bst_token err;
	if (l->done || skip(l, &err) < 0)
		return l->done && l->failed.kind != BST_TOK_ERROR ? mk(l, BST_TOK_EOF, l->line, l->col)
								  : l->failed;
	if (l->pos >= l->len) {
		l->done = 1;
		return mk(l, BST_TOK_EOF, l->line, l->col);
	}
	char c = l->s[l->pos];
	int line = l->line, col = l->col;
	switch (c) {
	case ';':
	case '{':
	case '}':
		adv(l);
		return mk(l, c == ';' ? BST_TOK_SEMI : c == '{' ? BST_TOK_LBRACE : BST_TOK_RBRACE,
			  line, col);
	case '"':
	case '\'':
		return quoted(l);
	default:
		return word(l);
	}
}

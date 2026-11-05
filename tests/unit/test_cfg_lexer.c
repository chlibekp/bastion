#include "config/lexer.h"
#include "core/arena.h"
#include "tap.h"

#include <string.h>

#define LIT(s) s, sizeof(s) - 1

static bst_arena *A;

static bst_lexer start(const char *s, size_t n)
{
	if (A)
		bst_arena_free(A);
	A = bst_arena_new(4096);
	bst_lexer l;
	bst_lexer_init(&l, A, s, n, "t.conf");
	return l;
}

static int is(bst_token t, bst_tok_kind k, const char *text, int line, int col)
{
	int ok = t.kind == k && t.line == line && t.col == col && strcmp(t.file, "t.conf") == 0;
	if (ok && text)
		ok = t.len == strlen(text) && memcmp(t.text, text, t.len) == 0;
	if (!ok)
		printf("# got kind=%d len=%zu at %d:%d\n", t.kind, t.len, t.line, t.col);
	return ok;
}

TEST(basic_statement)
{
	bst_lexer l = start(LIT("listen 80;"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "listen", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "80", 1, 8));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_SEMI, NULL, 1, 10));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_EOF, NULL, 1, 11));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_EOF, NULL, 1, 11));
}

TEST(delimiters_without_spaces)
{
	bst_lexer l = start(LIT("location / {\nfoo;bar}\nx{"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "location", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "/", 1, 10));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_LBRACE, NULL, 1, 12));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "foo", 2, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_SEMI, NULL, 2, 4));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "bar", 2, 5));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_RBRACE, NULL, 2, 8));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "x", 3, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_LBRACE, NULL, 3, 2));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_EOF, NULL, 3, 3));
}

TEST(semi_then_rbrace)
{
	bst_lexer l = start(LIT("a;}"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "a", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_SEMI, NULL, 1, 2));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_RBRACE, NULL, 1, 3));
}

TEST(comments_and_quotes)
{
	bst_lexer l = start(LIT("\"a#b\" # c"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_STRING_TPL, "a#b", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_EOF, NULL, 1, 10));
}

TEST(comment_rules)
{
	bst_lexer l = start(LIT("a#b c;# tail\n#full\nd '#x'"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "a#b", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "c", 1, 5));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_SEMI, NULL, 1, 6));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "d", 3, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_STRING_RAW, "#x", 3, 3));
}

TEST(escapes)
{
	bst_lexer l = start(LIT("\"\\n\\t\\\"\\\\\" '\\n' \"\""));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_STRING_TPL, "\n\t\"\\", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_STRING_RAW, "\\n", 1, 12));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_STRING_TPL, "", 1, 17));
}

TEST(unknown_escape_is_error)
{
	bst_lexer l = start(LIT("x \"a\\qb\""));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "x", 1, 1));
	bst_token t = bst_lexer_next(&l);
	ASSERT(is(t, BST_TOK_ERROR, NULL, 1, 5));
	ASSERT(t.msg != NULL);
}

TEST(unterminated)
{
	bst_lexer l = start(LIT("a\n  \"abc"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "a", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 2, 3));
	l = start(LIT("'abc"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 1));
	l = start(LIT("\"abc\\"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 1));
}

TEST(error_is_sticky)
{
	bst_lexer l = start(LIT("\"abc"));
	bst_token t = bst_lexer_next(&l);
	ASSERT_EQ(t.kind, BST_TOK_ERROR);
	for (int i = 0; i < 3; i++)
		ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 1));
}

TEST(newline_in_quotes)
{
	bst_lexer l = start(LIT("\"a\nb\" 'c\nd' e"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_STRING_TPL, "a\nb", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_STRING_RAW, "c\nd", 2, 4));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "e", 3, 4));
}

TEST(bom_crlf)
{
	bst_lexer l = start(LIT("\xEF\xBB\xBF" "a b;\r\nc;\r\n"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "a", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "b", 1, 3));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_SEMI, NULL, 1, 4));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "c", 2, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_SEMI, NULL, 2, 2));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_EOF, NULL, 3, 1));
}

TEST(crlf_in_comment_and_string)
{
	bst_lexer l = start(LIT("# c\r\n\"a\r\nb\" x"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_STRING_TPL, "a\r\nb", 2, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "x", 3, 4));
}

TEST(lone_cr_is_error)
{
	bst_lexer l = start(LIT("a\rb"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 2));
	l = start(LIT("a;\r"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "a", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_SEMI, NULL, 1, 2));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 3));
}

TEST(bom_elsewhere_is_error)
{
	bst_lexer l = start(LIT("a \xEF\xBB\xBF"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "a", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 3));
	l = start(LIT("ab\xEF\xBB\xBF" "c"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 3));
	l = start(LIT("\"\xEF\xBB\xBF\""));
	ASSERT_EQ(bst_lexer_next(&l).kind, BST_TOK_STRING_TPL);
}

TEST(bom_only_input)
{
	bst_lexer l = start(LIT("\xEF\xBB\xBF"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_EOF, NULL, 1, 1));
}

TEST(nul_byte)
{
	bst_lexer l = start("ab\0cd", 5);
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 3));
	l = start("a \0", 3);
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "a", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 3));
	l = start("\"a\0b\"", 5);
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 3));
	l = start("#c\0", 3);
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 3));
}

TEST(variables_stay_words)
{
	bst_lexer l = start(LIT("root $uri; key $remote_addr;"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "root", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "$uri", 1, 6));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_SEMI, NULL, 1, 10));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "key", 1, 12));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "$remote_addr", 1, 16));
}

TEST(env_expansion_one_word)
{
	bst_lexer l = start(LIT("a ${X:-y}; b/${P}/c{ ${Q}"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "a", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "${X:-y}", 1, 3));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_SEMI, NULL, 1, 10));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "b/${P}/c", 1, 12));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_LBRACE, NULL, 1, 20));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "${Q}", 1, 22));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_EOF, NULL, 1, 26));
}

TEST(env_expansion_swallows_delimiters)
{
	bst_lexer l = start(LIT("${a;b{c} x"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "${a;b{c}", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "x", 1, 10));
}

TEST(env_unterminated)
{
	bst_lexer l = start(LIT("x ${A"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_WORD, "x", 1, 1));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 3));
	l = start(LIT("${A b}"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 1));
	l = start(LIT("${"));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 1));
}

TEST(quote_inside_word_is_error)
{
	bst_lexer l = start(LIT("ab\"c\""));
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 3));
}

TEST(token_limit)
{
	size_t n = BST_LEX_MAX_TOKEN + 1;
	char *buf = malloc(n + 4);
	ASSERT(buf != NULL);
	memset(buf, 'a', n + 4);
	bst_lexer l = start(buf, BST_LEX_MAX_TOKEN);
	bst_token t = bst_lexer_next(&l);
	ASSERT_EQ(t.kind, BST_TOK_WORD);
	ASSERT_EQ(t.len, BST_LEX_MAX_TOKEN);
	l = start(buf, n);
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 1));
	/* Strings: positions point at the opening quote. */
	buf[0] = '"';
	buf[BST_LEX_MAX_TOKEN + 1] = '"';
	l = start(buf, BST_LEX_MAX_TOKEN + 2);
	t = bst_lexer_next(&l);
	ASSERT_EQ(t.kind, BST_TOK_STRING_TPL);
	ASSERT_EQ(t.len, BST_LEX_MAX_TOKEN);
	buf[BST_LEX_MAX_TOKEN + 1] = 'a';
	buf[BST_LEX_MAX_TOKEN + 2] = '"';
	l = start(buf, BST_LEX_MAX_TOKEN + 3);
	ASSERT(is(bst_lexer_next(&l), BST_TOK_ERROR, NULL, 1, 1));
	free(buf);
}

TEST(sample_config)
{
	const char *src = "server {\n  listen 0.0.0.0:80 reuseport;\n"
			  "  location ~* \\.php$ { return 404 \"nope\\n\"; }\n}\n";
	bst_lexer l = start(src, strlen(src));
	int n = 0;
	bst_token t;
	while ((t = bst_lexer_next(&l)).kind != BST_TOK_EOF) {
		ASSERT(t.kind != BST_TOK_ERROR);
		n++;
	}
	ASSERT_EQ(n, 16);
	ASSERT_EQ(t.line, 5);
}

TAP_MAIN()

/* Config lexer: one pass over the bytes, no recursion, no allocation except decoded
 * double-quoted strings, which live in the caller's arena.
 *
 * Tokens: WORD (raw text, `$var` and `${ENV}` untouched; the directive's argspec decides
 * later whether it is a template), STRING_TPL ("double", escapes decoded), STRING_RAW ('single', no processing), SEMI, LBRACE, RBRACE,
 * EOF, ERROR. A quoted string may contain literal newlines. In "double" strings \" \\ \n \t \r
 * decode and any other \x keeps both bytes (nginx; regexes like "\.php$" work). A string
 * must be followed by whitespace, `;`, `{`, `}` or EOF, else ERROR.
 *
 * Words end at whitespace, `;`, `{`, `}` or a quote character (a quote inside a bare word
 * is an ERROR). `foo;bar`, `foo{` and `a;}` split without spaces. A `{` right after `$`
 * stays in the word and runs to its `}` (so `${X:-y}` is one WORD); an unterminated `${`
 * is an ERROR. A `#` starts a comment only at the start of a token, outside quotes, so
 * `a#b` is one word (as in nginx).
 *
 * Positions: line and col are 1-based, col counts bytes. Only LF starts a line; CRLF is one
 * newline; a lone CR outside quotes is an ERROR. A BOM at offset 0 is skipped and does not
 * count toward col 1. Anywhere else it is ordinary bytes (an ERROR outside a string).
 * NUL bytes are an ERROR everywhere. A token longer than BST_LEX_MAX_TOKEN bytes is an
 * ERROR, never truncated. An ERROR token carries a static message in .msg and the position
 * of the offending byte (for unterminated strings, the opening quote); after it every
 * call returns ERROR again.
 *
 * Token text points into the input (WORD, STRING_RAW) or the arena (STRING_TPL) and is
 * not NUL-terminated. Both outlive the lexer as long as input and arena do. */
#ifndef BST_CONFIG_LEXER_H
#define BST_CONFIG_LEXER_H

#include "core/arena.h"

#include <stddef.h>

#define BST_LEX_MAX_TOKEN ((size_t)1 << 20)

typedef enum bst_tok_kind {
	BST_TOK_WORD,
	BST_TOK_STRING_RAW,
	BST_TOK_STRING_TPL,
	BST_TOK_SEMI,
	BST_TOK_LBRACE,
	BST_TOK_RBRACE,
	BST_TOK_EOF,
	BST_TOK_ERROR,
} bst_tok_kind;

typedef struct bst_token {
	bst_tok_kind kind;
	const char *text; /* WORD and strings; NULL otherwise */
	size_t len;
	const char *file;
	int line;
	int col;
	const char *msg; /* ERROR only: static description */
} bst_token;

#ifdef BST_TEST
extern int bst_lex_test_fail_alloc; /* test hook: arena allocation fails */
#endif

typedef struct bst_lexer {
	const char *s;
	size_t len;
	size_t pos;
	const char *file;
	bst_arena *arena;
	int line;
	int col;
	bst_token failed; /* sticky ERROR */
	int done;
} bst_lexer;

/* Signature differs from the plan's Interfaces line: takes the arena for decoded strings. */
void bst_lexer_init(bst_lexer *l, bst_arena *arena, const char *text, size_t len,
		    const char *file);
bst_token bst_lexer_next(bst_lexer *l);

#endif

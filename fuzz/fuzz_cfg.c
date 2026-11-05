/* libFuzzer harness for the config lexer. The input is copied to an exact-size heap block
 * so ASan flags any read past len. Properties: the lexer reaches EOF or ERROR within
 * len + 2 tokens, positions never go backwards and stay 1-based, text lies inside the
 * input (or arena), and ERROR is sticky. The same input then goes through the parser with
 * includes disabled, so no input can read host files; env expansion stays on. A success
 * must walk cleanly and a failure must carry a message and a position. */
#include "config/lexer.h"
#include "config/parser.h"
#include "core/arena.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	char *copy = malloc(size ? size : 1);
	bst_arena *a = bst_arena_new(1 << 16);
	if (!copy || !a)
		abort();
	memcpy(copy, d, size);
	bst_lexer l;
	bst_lexer_init(&l, a, copy, size, "fuzz");
	int pline = 1, pcol = 1;
	size_t n = 0;
	for (;; n++) {
		if (n > size + 2)
			abort();
		bst_token t = bst_lexer_next(&l);
		if (t.line < 1 || t.col < 1)
			abort();
		if (t.kind == BST_TOK_ERROR || t.kind == BST_TOK_EOF) {
			if (t.kind == BST_TOK_ERROR) {
				bst_token u = bst_lexer_next(&l);
				if (u.kind != BST_TOK_ERROR || u.line != t.line || u.col != t.col)
					abort();
			}
			break;
		}
		if (t.line < pline || (t.line == pline && t.col < pcol))
			abort();
		pline = t.line;
		pcol = t.col;
		if (t.kind == BST_TOK_WORD || t.kind == BST_TOK_STRING_RAW) {
			if (t.text < copy || t.text + t.len > copy + size)
				abort();
		}
		if (t.len > BST_LEX_MAX_TOKEN)
			abort();
	}
	bst_arena_free(a);

	a = bst_arena_new(1 << 16);
	if (!a)
		abort();
	bst_err e;
	bst_cfg_opts o = {.no_include = 1};
	bst_ast *ast = bst_cfg_parse_string(copy, size, "fuzz", &o, a, &e);
	if (ast) {
		size_t cnt = 0;
		for (const bst_ast_node *x = bst_ast_next(ast, NULL); x; x = bst_ast_next(ast, x)) {
			if (!x->name || x->name_len == 0 || strlen(x->name) != x->name_len)
				abort();
			for (size_t i = 0; i < x->nargs; i++)
				if (strlen(x->args[i].text) != x->args[i].len)
					abort();
			if (++cnt > size)
				abort();
		}
	} else if (e.msg[0] == 0 || e.line < 0 || e.col < 0 || (e.line > 0 && !e.file)) {
		abort();
	}
	bst_arena_free(a);
	free(copy);
	return 0;
}

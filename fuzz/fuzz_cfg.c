/* libFuzzer harness for the config lexer. The input is copied to an exact-size heap block
 * so ASan flags any read past len. Properties: the lexer reaches EOF or ERROR within
 * len + 2 tokens, positions never go backwards and stay 1-based, text lies inside the
 * input (or arena), and ERROR is sticky. */
#include "config/lexer.h"
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
	free(copy);
	return 0;
}

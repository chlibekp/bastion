/* Error report filled in by parsers and loaders. msg is a fixed-size, NUL-terminated
 * description. Producers must not copy raw input bytes into it unescaped: messages
 * reach logs. file may be NULL; line and col are 1-based, 0 when unknown. */
#ifndef BST_ERR_H
#define BST_ERR_H

typedef struct bst_err {
	char msg[256];
	const char *file;
	int line;
	int col;
} bst_err;

/* Sets msg (truncated to fit) and clears file, line and col. A NULL err is ignored,
 * so callers that do not want details may pass NULL. */
void bst_err_set(bst_err *e, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#endif

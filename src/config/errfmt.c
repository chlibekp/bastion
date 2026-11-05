/* See errfmt.h. */
#include "config/errfmt.h"

#include "config/schema.h"

#include <string.h>

static void shown_limit(const char *s, size_t len, size_t limit, char *out, size_t cap)
{
	size_t n = 0, lim = len < limit ? len : limit;
	for (size_t i = 0; i < lim && n + 4 < cap; i++) {
		unsigned char c = (unsigned char)s[i];
		out[n++] = (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') ? (char)c : '?';
	}
	if (lim < len && n + 4 < cap) {
		out[n++] = '.';
		out[n++] = '.';
		out[n++] = '.';
	}
	out[n] = 0;
}

void bst_cfg_shown(const char *s, size_t len, char *out, size_t cap)
{
	shown_limit(s, len, BST_SCHEMA_MAX_TOKEN_SHOWN, out, cap);
}

void bst_cfg_shown_file(const char *file, char *out, size_t cap)
{
	if (file == NULL)
		file = "?";
	shown_limit(file, strlen(file), BST_CFG_SHOWN_FILE, out, cap);
}

void bst_cfg_err_at(bst_err *e, const bst_loc *loc)
{
	if (e == NULL)
		return;
	e->file = loc ? loc->file : NULL;
	e->line = loc ? loc->line : 0;
	e->col = loc ? loc->col : 0;
}

#include "handlers/mime.h"

#include <string.h>

typedef struct ent {
	const char *ext;
	const char *type;
} ent;

static const ent table[] = {
#define X(e, t) { e, t },
#include "handlers/mime_table.def"
#undef X
};

static bool ext_eq(const char *a, size_t alen, const char *b, size_t blen)
{
	if (alen != blen)
		return false;
	for (size_t i = 0; i < alen; i++) {
		char c = a[i] >= 'A' && a[i] <= 'Z' ? (char)(a[i] + 32) : a[i];
		if (c != b[i])
			return false;
	}
	return true;
}

const char *bst_mime_lookup(const bst_cfg_list *custom, const char *name, size_t len,
			    const char *dflt)
{
	size_t base = len;
	while (base > 0 && name[base - 1] != '/')
		base--;
	size_t dot = len;
	while (dot > base && name[dot - 1] != '.')
		dot--;
	if (dot <= base + 1) /* no dot, or only the leading one of ".bashrc" */
		return dflt;
	const char *ext = name + dot;
	size_t elen = len - dot;
	for (size_t i = custom != NULL ? custom->n : 0; i > 0; i--) {
		const bst_cfg_mime *m = custom->items[i - 1];
		if (ext_eq(ext, elen, m->ext, m->ext_len))
			return m->type;
	}
	for (size_t i = 0; i < sizeof table / sizeof table[0]; i++)
		if (ext_eq(ext, elen, table[i].ext, strlen(table[i].ext)))
			return table[i].type;
	return dflt;
}

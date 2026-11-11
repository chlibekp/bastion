/* Media types of file extensions (`types`, `default_type`). */
#ifndef BST_HANDLERS_MIME_H
#define BST_HANDLERS_MIME_H

#include "config/compile.h"

/* The type for a file name: the entries of custom (from `types`, the last match wins), then the
 * built-in table, else dflt. The extension is what follows the last '.' of the last path
 * component, compared without case; a name with no extension (or only a leading dot) gets dflt. */
const char *bst_mime_lookup(const bst_cfg_list *custom, const char *name, size_t len,
			    const char *dflt);

#endif

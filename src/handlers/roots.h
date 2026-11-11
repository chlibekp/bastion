/* Serving roots are opened once, in the master, before the sandbox (the workers inherit the
 * descriptors). */
#ifndef BST_HANDLERS_ROOTS_H
#define BST_HANDLERS_ROOTS_H

#include "config/compile.h"
#include "core/err.h"

/* Opens every root of cfg (O_PATH|O_DIRECTORY). 0, or -1 with err naming the path and the reason. */
int bst_roots_open(bst_config *cfg, bst_err *err);
void bst_roots_close(bst_config *cfg);

/* The paths the sandbox must allow reading: every root. Fills out (a malloc'd array of the
 * config's own strings; free the array), returns the count, 0 with *out NULL when none. */
size_t bst_roots_paths(const bst_config *cfg, const char ***out);

#endif

/* What sandbox.c, landlock.c and namespaces.c share. */
#ifndef BST_PROC_SANDBOX_PRIV_H
#define BST_PROC_SANDBOX_PRIV_H

#include "proc/sandbox.h"

#include <stdbool.h>

/* fn(arg) on the calling thread and on every pool thread of the loop given to
 * bst_sandbox_set_loop, and back when all have run it. 0, or a negative errno. */
int bst_sandbox_each_thread(void (*fn)(void *), void *arg);

/* bst_ns_enter gave this child its namespaces and private root. */
bool bst_ns_active(void);

/* Landlock on every thread. 0 with *abi set, 1 when the kernel has none, -1 with e set. */
int bst_landlock_apply(const bst_sandbox_paths *p, int *abi, bst_err *e);

#endif

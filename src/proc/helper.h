/* The helper: one unprivileged process with its own loop, for work that must exist only once.
 * Later phases give it work (architecture section 1); here it starts, stays up and stops. */
#ifndef BST_PROC_HELPER_H
#define BST_PROC_HELPER_H

#include "proc/runtime.h"

/* Runs the helper in a forked child. Never returns. */
void bst_helper_main(bst_runtime *rt) __attribute__((noreturn));

#endif

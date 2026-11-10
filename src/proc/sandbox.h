/* The sandbox of workers and the helper (architecture section 8). Workers parse attacker input,
 * so this is what contains a compromise. Master stays outside it.
 *
 * The order, and where each step lives:
 *   1. Files, rings, shared memory, the aio pool: bst_child_start, bst_child_loop.
 *   2. Namespaces: bst_ns_fork in master for PID, bst_ns_enter in the child for the rest.
 *   3. The drop: bst_child_drop, then bst_sandbox_drop_caps. PR_SET_PDEATHSIG comes after it.
 *   4-6. bst_sandbox_apply: no_new_privs, not dumpable, no core; Landlock; seccomp.
 * An SQPOLL ring moves from step 1 to after step 3: see bst_child_loop_and_drop.
 *
 * Credentials and no_new_privs belong to a thread, not to a process, and the aio pool started in
 * step 1. So steps 3 to 5 run on every pool thread too (bst_aio_each_thread); only setuid, by way
 * of libc, and SECCOMP_FILTER_FLAG_TSYNC reach them on their own.
 *
 * What cannot be had: Landlock or seccomp missing from the kernel, or a namespace or the bounding
 * set not permitted, logs a warning and carries on, unless the directive says `require`, which
 * makes it a startup error. TSYNC failing is always one: pool threads would run free. */
#ifndef BST_PROC_SANDBOX_H
#define BST_PROC_SANDBOX_H

#include "config/compile.h"
#include "core/err.h"
#include "io/loop.h"

#include <stddef.h>

typedef enum bst_sandbox_role { BST_SANDBOX_WORKER, BST_SANDBOX_HELPER } bst_sandbox_role;

/* read: serving roots and extra_read. write: cache and temp directories and extra_write. */
typedef struct bst_sandbox_paths {
	const char *const *read;
	size_t nread;
	const char *const *write;
	size_t nwrite;
} bst_sandbox_paths;

/* Applies steps 4 to 6 to the calling process. 0, or -1 with err set: the child must not go on. */
int bst_sandbox_apply(const bst_cfg_sandbox *cfg, bst_sandbox_role role,
		      const bst_sandbox_paths *paths, bst_err *err);

/* The loop whose pool threads the steps must reach. NULL (the default): the caller is alone. */
void bst_sandbox_set_loop(bst_loop *l);

/* Step 3: call before the setuid when the uid will change, or the caller can no longer drop its
 * bounding set after it. 0, or -1 with err set. */
int bst_sandbox_keep_caps(bst_err *err);
/* Step 3: every capability set of every thread, bounding, ambient and inheritable included. A
 * process without CAP_SETPCAP (master was not root) cannot empty its bounding set: a warning,
 * or under `require` an error. 0, or -1 with err set. */
int bst_sandbox_drop_caps(const bst_cfg_sandbox *cfg, bst_err *err);

/* In a sanitizer build, before step 2 of any child: what a report needs later has to be open and
 * cached by then, and a sandboxed child gives up its leak check, which clones a thread and reads
 * /proc. Master keeps it. tag names the child in its report file. Nothing in other builds. */
void bst_sandbox_sanitizer_prepare(const char *tag);

/* Registers restrictions on a ring that is still disabled: exactly the opcodes, SQE flags and
 * register opcodes the backend needs, cut down to what this kernel's probe knows, because the
 * kernel refuses an opcode it has never heard of. Ring operations are not syscalls, so seccomp
 * never sees them. Above all this closes REGISTER_BUFFERS: a plain ring created as root escapes
 * RLIMIT_MEMLOCK. It does not make SQPOLL safe: restrictions leave CONNECT open, so an SQPOLL
 * ring is still created after the drop.
 * Fits bst_uring_pre_enable_: 0, or a negative errno. */
struct io_uring;
int bst_uring_restrict(struct io_uring *ring);
/* Every ring this process creates from now on gets bst_uring_restrict before it is enabled. */
void bst_sandbox_restrict_rings(void);

#endif

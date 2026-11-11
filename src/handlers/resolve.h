/* Opening a file below a serving root, safely. The path has been normalized by the router
 * (route/uri.h) and the kernel is the second wall: the open is openat2 relative to the root's
 * descriptor with RESOLVE_BENEATH, so no path, link or race can name anything outside it.
 *
 * The open and the stat are blocking disk work: bst_file_open runs them on the aio pool
 * (io/aio.h) and calls back on the loop thread. (Design note: the plan names IORING_OP_OPENAT2 for
 * the io_uring backend; the pool is used on both backends so one code path, one seccomp row and
 * one cancel rule serve both. A later phase may move the uring case onto the ring.) */
#ifndef BST_HANDLERS_RESOLVE_H
#define BST_HANDLERS_RESOLVE_H

#include "config/compile.h"
#include "core/str.h"
#include "handlers/ofcache.h"
#include "proc/worker.h"

typedef struct bst_file_policy {
	bst_symlinks symlinks;
	bool dotfiles_allow;
} bst_file_policy;

/* True when a component of the relative path begins with '.'. */
bool bst_path_has_dotfile(const char *rel, size_t len);

/* The blocking core, for the pool and for tests. rel is relative to root_fd ("" or "." is the root
 * itself) and NUL-terminated. 0 with *out a file (regular, directory or something else: look at
 * mode), or an errno: ENOENT, ENOTDIR, ELOOP (a link under `symlinks off`), EXDEV (the path
 * resolves outside the root), EACCES. */
int bst_file_open_sync(int root_fd, const char *rel, bst_symlinks sl, bst_file **out);

/* cb(ud, file, 0) with a reference the callee must drop, or cb(ud, NULL, errno). A path with a
 * dotfile component under `dotfiles deny` fails with ENOENT before any disk access. */
typedef void (*bst_file_cb)(void *ud, bst_file *f, int err);
typedef struct bst_file_req bst_file_req;

/* Starts the open. Returns a handle valid until cb runs, or NULL when cb already ran (a cache hit,
 * an early refusal) or the job could not be queued (cb got EAGAIN). bst_file_open_cancel: cb will
 * not be called; the result is dropped. Use it from a handler's on_reset. */
bst_file_req *bst_file_open(bst_worker *w, int root_fd, bst_str rel, bst_file_policy p,
			    bst_file_cb cb, void *ud);
void bst_file_open_cancel(bst_file_req *r);

#endif

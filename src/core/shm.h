/* Anonymous shared memory (memfd) with a sealed size. */
#ifndef BST_SHM_H
#define BST_SHM_H

#include <stdbool.h>
#include <stddef.h>

/* Create a memfd of exactly size bytes, seal it against grow and shrink, and map it
 * shared read-write. The fd is close-on-exec and returned in *fd_out (closed if fd_out
 * is NULL). NULL on failure with errno set. */
void *bst_shm_create(const char *name, size_t size, int *fd_out);
/* Map an existing sealed memfd. Fails if the fd's size is not exactly size. */
void *bst_shm_attach(int fd, size_t size);

/* ---- regions that survive a reload (proc/reload.h) ----
 *
 * A region created with bst_shm_create_kept keeps its fd in a small table, so master can hand
 * it to the next image. In that image, bst_shm_inherited_add registers the fds it was given, and
 * bst_shm_create_kept maps the first unused one of the same name and size instead of creating a
 * new region, with *reused set: the caller then skips its initialisation. A size that no longer
 * matches gets a fresh region (the config changed its layout). */
#define BST_SHM_KEPT_MAX 32
void *bst_shm_create_kept(const char *name, size_t size, bool *reused);
void bst_shm_inherited_add(const char *name, int fd);
/* Closes inherited regions nobody took. */
void bst_shm_inherited_close_untaken(void);
/* The i-th kept region: false past the end. */
bool bst_shm_kept_get(size_t i, const char **name, int *fd);
/* The fd of the kept region mapped at p, or -1. */
int bst_shm_kept_fd(const void *p);

/* ---- regions children only read ----
 *
 * Memory a lower-privileged child writes is input to whoever reads it, so a region master
 * (or the helper) writes and workers only read gets a second, read-only mapping of the same
 * memfd, made from a fresh O_RDONLY description (/proc/self/fd): the kernel then refuses an
 * mprotect that would make it writable again. bst_shm_ro_view returns that view, or NULL with
 * errno set. In a child, bst_shm_child_readonly unmaps the read-write mapping of every region
 * registered this way (helper: those the helper does not write), so the child holds only the
 * read-only view and a write through any pointer to the region faults. Call it before the
 * child drops privileges, with no fd of the region left open in the child. */
#define BST_SHM_RO_MAX 16
const void *bst_shm_ro_view(void *rw, int fd, size_t size, bool helper_writes);
void bst_shm_child_readonly(bool helper);

#endif

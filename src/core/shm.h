/* Anonymous shared memory (memfd) with a sealed size. */
#ifndef BST_SHM_H
#define BST_SHM_H

#include <stddef.h>

/* Create a memfd of exactly size bytes, seal it against grow and shrink, and map it
 * shared read-write. The fd is close-on-exec and returned in *fd_out (closed if fd_out
 * is NULL). NULL on failure with errno set. */
void *bst_shm_create(const char *name, size_t size, int *fd_out);
/* Map an existing sealed memfd. Fails if the fd's size is not exactly size. */
void *bst_shm_attach(int fd, size_t size);

#endif

#include "core/shm.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

void *bst_shm_create(const char *name, size_t size, int *fd_out)
{
	if (size == 0) {
		errno = EINVAL;
		return NULL;
	}
	int fd = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd < 0)
		return NULL;
	if (ftruncate(fd, (off_t)size) != 0 ||
	    fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) != 0)
		goto fail;
	void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		goto fail;
	if (fd_out)
		*fd_out = fd;
	else
		close(fd);
	return p;
fail:;
	int e = errno;
	close(fd);
	errno = e;
	return NULL;
}

void *bst_shm_attach(int fd, size_t size)
{
	struct stat st;
	if (size == 0 || fstat(fd, &st) != 0)
		return NULL;
	if (st.st_size < 0 || (unsigned long long)st.st_size != size) {
		errno = EINVAL;
		return NULL;
	}
	void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	return p == MAP_FAILED ? NULL : p;
}

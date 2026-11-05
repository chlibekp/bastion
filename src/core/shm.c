#include "core/shm.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef MFD_NOEXEC_SEAL
#define BST_MFD_NOEXEC_SEAL MFD_NOEXEC_SEAL
#else
#define BST_MFD_NOEXEC_SEAL 0x0008U
#endif

void *bst_shm_create(const char *name, size_t size, int *fd_out)
{
	if (size == 0) {
		errno = EINVAL;
		return NULL;
	}
	/* MFD_NOEXEC_SEAL (Linux 6.3) keeps the memory from ever becoming executable; a 6.1
	 * kernel rejects the unknown flag with EINVAL, so fall back to the plain call. */
	int fd = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING | BST_MFD_NOEXEC_SEAL);
	if (fd < 0 && errno == EINVAL)
		fd = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd < 0)
		return NULL;
	/* F_SEAL_SEAL last: nobody, including a process that receives the fd, can add seals
	 * or lift the size guarantee later. */
	if (ftruncate(fd, (off_t)size) != 0 ||
	    fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0)
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

/* Sealing of bst_shm_create memory. Also compiled and run inside the VM guest
 * (tests/vm/test_kernel_features.py) to prove it on Linux 6.1 and current kernels. */
#include "tap.h"

#include "core/shm.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC 0x0020
#endif
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif

/* True when this kernel (6.3+) knows MFD_NOEXEC_SEAL. */
static int kernel_has_noexec_seal(void)
{
	int fd = memfd_create("probe", MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL);
	if (fd < 0)
		return 0;
	close(fd);
	return 1;
}

TEST(shm_is_fully_sealed)
{
	int fd = -1;
	void *p = bst_shm_create("seal-test", 4096, &fd);
	ASSERT(p != NULL);
	ASSERT(fd >= 0);
	int seals = fcntl(fd, F_GET_SEALS);
	ASSERT(seals >= 0);
	ASSERT(seals & F_SEAL_GROW);
	ASSERT(seals & F_SEAL_SHRINK);
	ASSERT(seals & F_SEAL_SEAL);
	/* On a kernel that has MFD_NOEXEC_SEAL a silent fallback would be a bug. */
	if (kernel_has_noexec_seal())
		ASSERT(seals & F_SEAL_EXEC);
	/* No further seal can be added (that would otherwise let a holder freeze writes). */
	errno = 0;
	ASSERT_EQ(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE), -1);
	ASSERT_EQ(errno, EPERM);
	/* Size cannot change. */
	ASSERT(ftruncate(fd, 8192) != 0);
	ASSERT(ftruncate(fd, 100) != 0);
	munmap(p, 4096);
	close(fd);
}

TEST(shm_zero_size_rejected)
{
	errno = 0;
	ASSERT(bst_shm_create("zero", 0, NULL) == NULL);
	ASSERT_EQ(errno, EINVAL);
}

TAP_MAIN()

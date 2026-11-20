/* Sealing of bst_shm_create memory. Also compiled and run inside the VM guest
 * (tests/vm/test_kernel_features.py) to prove it on Linux 6.1 and current kernels. */
#include "tap.h"

#include "core/shm.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/wait.h>
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

/* Security review H1/M5: a child keeps only the read-only view of a master-written region.
 * It still sees master's writes, its writable mapping is gone, and mprotect cannot make the
 * view writable (the view's description is O_RDONLY). The helper keeps a region it writes. */
static int child_checks(const volatile char *ro, void *rw, size_t sz, bool helper)
{
	bst_shm_child_readonly(helper);
	if (ro[0] != 'm')
		return 2;
	errno = 0;
	if (mprotect((void *)(uintptr_t)ro, sz, PROT_READ | PROT_WRITE) == 0 || errno != EACCES)
		return 3;
	unsigned char vec[1];
	int gone = mincore(rw, sz, vec) != 0 && errno == ENOMEM;
	if (helper == gone) /* unmapped in a worker, kept in the helper */
		return 4;
	return 0;
}

TEST(shm_ro_view_in_child)
{
	int fd = -1;
	size_t sz = 4096;
	char *rw = bst_shm_create("ro-test", sz, &fd);
	ASSERT(rw != NULL);
	const volatile char *ro = bst_shm_ro_view(rw, fd, sz, true);
	ASSERT(ro != NULL);
	close(fd);
	rw[0] = 'm';
	ASSERT_EQ(ro[0], 'm');
	for (int helper = 0; helper < 2; helper++) {
		pid_t pid = fork();
		ASSERT(pid >= 0);
		if (pid == 0)
			_exit(child_checks(ro, rw, sz, helper != 0));
		int st = 0;
		ASSERT_EQ(waitpid(pid, &st, 0), pid);
		ASSERT(WIFEXITED(st));
		ASSERT_EQ(WEXITSTATUS(st), 0);
	}
	ASSERT(bst_shm_ro_view(rw, -1, sz, false) == NULL);
}

TAP_MAIN()

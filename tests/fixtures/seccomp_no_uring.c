/* Test wrapper: makes io_uring_setup fail with EPERM (a seccomp filter, as a container
 * runtime's default profile does), then execs the command. The filter survives exec.
 * With --no-openat2 it instead makes openat2 fail with ENOSYS, as systemd's RestrictSUIDSGID=yes
 * does (openat2's mode sits behind a pointer the filter cannot read).
 * usage: seccomp_no_uring [--no-openat2] cmd [args...] */
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define ARCH AUDIT_ARCH_AARCH64
#else
#error "unsupported architecture"
#endif

int main(int argc, char **argv)
{
	unsigned nr = __NR_io_uring_setup, err = EPERM;
	int first = 1;
	if (argc > 1 && strcmp(argv[1], "--no-openat2") == 0) {
		nr = __NR_openat2;
		err = ENOSYS;
		first = 2;
	}
	if (argc < first + 1) {
		fprintf(stderr, "usage: %s [--no-openat2] cmd [args...]\n", argv[0]);
		return 2;
	}
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | err),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {.len = (unsigned short)(sizeof f / sizeof f[0]), .filter = f};
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
		perror("seccomp");
		return 2;
	}
	execv(argv[first], argv + first);
	perror("execv");
	return 127;
}

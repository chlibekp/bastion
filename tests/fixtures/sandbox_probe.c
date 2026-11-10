/* BST_TEST_SANDBOX_PROBE: a child attempts something from inside its sandbox, as a compromised one
 * would. Compiled into every build but release (Makefile); `make check-release` proves it gone.
 * Every attempt is a raw syscall: no libc wrapper or sanitizer interceptor decides anything.
 *
 *   BST_TEST_SANDBOX_PROBE=<slot|helper>:<probe>[,<probe>...]
 *   BST_TEST_SANDBOX_PROBE_ONCE=<path>   only in the child that finds path and removes it
 *
 * A probe is a name from the table below, with `:<arg>` for those that take one, and `pool:` in
 * front to run on an aio pool thread. It logs `sandbox probe: <name> res=<n> errno=<e>` if it
 * survives. uring_* probes wait for their own completions, which would eat the loop's, so they
 * run before the loop has anything armed; the others run once READY is out, so a test can start a
 * server normally and watch its worker die. */
#ifdef BST_TEST
#include "core/log.h"
#include "io/aio.h"
#include "proc/test_hooks.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <termios.h>
#include <unistd.h>

#define NAME_MAX_LEN 256

static bool fire;
static char spec[1024];
static bst_loop *loop;
static int cold_fd = -1;

static long sc_socket(long dom, long type, long proto)
{
	long fd = syscall(SYS_socket, dom, type, proto);
	if (fd >= 0)
		close((int)fd);
	return fd;
}

static long sc_execve(const char *arg)
{
	(void)arg;
	static char *const argv[] = { (char *)"/bin/true", NULL };
	return syscall(SYS_execve, "/bin/true", argv, environ);
}

static long sc_ptrace(const char *arg)
{
	(void)arg;
	return syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
}

static long sc_socket_raw(const char *a)
{
	(void)a;
	return sc_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
}

static long sc_socket_packet(const char *a)
{
	(void)a;
	return sc_socket(AF_PACKET, SOCK_RAW, 0);
}

static long sc_socket_netlink(const char *a)
{
	(void)a;
	return sc_socket(AF_NETLINK, SOCK_DGRAM, 0);
}

static long sc_socket_unix(const char *a)
{
	(void)a;
	return sc_socket(AF_UNIX, SOCK_STREAM, 0);
}

static long sc_socket_inet_raw_type(const char *a)
{
	(void)a;
	return sc_socket(AF_INET, SOCK_PACKET, 0);
}

static long sc_socket_tcp(const char *a)
{
	(void)a;
	return sc_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
}

static long sc_socket_udp(const char *a)
{
	(void)a;
	return sc_socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
}

static long sc_bpf(const char *a)
{
	(void)a;
	union bpf_attr attr;
	memset(&attr, 0, sizeof attr);
	return syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof attr);
}

static long sc_mount(const char *a)
{
	(void)a;
	return syscall(SYS_mount, "none", "/", "tmpfs", 0L, NULL);
}

static long sc_memfd(const char *a)
{
	(void)a;
	long fd = syscall(SYS_memfd_create, "probe", 0);
	if (fd >= 0)
		close((int)fd);
	return fd;
}

static long sc_open(const char *a)
{
	(void)a;
	return syscall(SYS_openat, AT_FDCWD, "/etc/passwd", O_RDONLY);
}

static long sc_read_file(const char *path)
{
	static char buf[65536];
	long fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	long n = syscall(SYS_read, fd, buf, sizeof buf);
	int e = errno;
	close((int)fd);
	errno = e;
	return n;
}

static long sc_write_file(const char *path)
{
	long fd = syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd >= 0)
		close((int)fd);
	return fd;
}

static long sc_mmap_exec(const char *a)
{
	(void)a;
	return syscall(SYS_mmap, NULL, 4096L, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1L,
		       0L) == (long)MAP_FAILED ? -1 : 0;
}

static long sc_mmap_rw(const char *a)
{
	(void)a;
	return syscall(SYS_mmap, NULL, 4096L, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
		       -1L, 0L) == (long)MAP_FAILED ? -1 : 0;
}

static long sc_mprotect_exec(const char *a)
{
	(void)a;
	void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	return syscall(SYS_mprotect, p, 4096L, PROT_READ | PROT_EXEC);
}

static long sc_prctl(const char *a)
{
	(void)a;
	return syscall(SYS_prctl, PR_GET_NAME, spec, 0L, 0L, 0L);
}

static long sc_dumpable(const char *a)
{
	(void)a;
	return syscall(SYS_prctl, PR_GET_DUMPABLE, 0L, 0L, 0L, 0L);
}

static long sc_ioctl_tiocsti(const char *a)
{
	(void)a;
	return syscall(SYS_ioctl, 0, TIOCSTI, "x");
}

static long sc_fcntl_setown(const char *a)
{
	(void)a;
	return syscall(SYS_fcntl, bst_log_fd(), F_SETOWN, 1L);
}

static long sc_fcntl_getfl(const char *a)
{
	(void)a;
	return syscall(SYS_fcntl, bst_log_fd(), F_GETFL);
}

static long sc_setsockopt_ulp(const char *a)
{
	(void)a;
	long fd = syscall(SYS_socket, AF_INET, SOCK_STREAM, 0L);
	return syscall(SYS_setsockopt, fd, IPPROTO_TCP, 31 /* TCP_ULP */, "tls", 4L);
}

static uint32_t futex_word;

static long sc_futex_pi(const char *a)
{
	(void)a;
	return syscall(SYS_futex, &futex_word, FUTEX_LOCK_PI, 0L, NULL, NULL, 0L);
}

static long sc_futex_wait_1500ms(const char *a)
{
	(void)a;
	struct timespec ts = { 1, 500000000 };
	bst_log(BST_LOG_INFO, "sandbox probe: waiting");
	return syscall(SYS_futex, &futex_word, FUTEX_WAIT_PRIVATE, 0L, &ts, NULL, 0L);
}

static long sc_tgkill_other(const char *a)
{
	(void)a;
	return syscall(SYS_tgkill, 1L, 1L, 0L);
}

static long sc_tgkill_self(const char *a)
{
	(void)a;
	return syscall(SYS_tgkill, (long)getpid(), syscall(SYS_gettid), 0L);
}

static long sc_kill(const char *a)
{
	(void)a;
	return syscall(SYS_kill, 1L, 0L);
}

static long sc_setuid(const char *a)
{
	(void)a;
	return syscall(SYS_setuid, 0L);
}

static long sc_chroot(const char *a)
{
	(void)a;
	return syscall(SYS_chroot, "/");
}

static long sc_unshare(const char *a)
{
	(void)a;
	return syscall(SYS_unshare, (long)CLONE_NEWUSER);
}

static long sc_seccomp(const char *a)
{
	(void)a;
	return syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0L, NULL);
}

static long sc_io_uring_setup(const char *a)
{
	(void)a;
	return syscall(SYS_io_uring_setup, 2L, NULL);
}

static long sc_accept4(const char *a)
{
	(void)a;
	return syscall(SYS_accept4, -1L, NULL, NULL, 0L);
}

static long sc_fork(const char *a)
{
	(void)a;
	return syscall(SYS_clone, (long)SIGCHLD, 0L, 0L, 0L, 0L);
}

static long sc_clone_thread(const char *a)
{
	(void)a;
	static char stack[65536] __attribute__((aligned(16)));
	return syscall(SYS_clone, (long)(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
					 CLONE_THREAD | CLONE_SYSVSEM),
		       stack + sizeof stack, 0L, 0L, 0L);
}

static long sc_clone_vfork(const char *a)
{
	(void)a;
	return syscall(SYS_clone, (long)(CLONE_VFORK | CLONE_VM | SIGCHLD), 0L, 0L, 0L, 0L);
}

static long sc_clone3(const char *a)
{
	(void)a;
	uint64_t args[11];
	memset(args, 0, sizeof args);
	return syscall(SYS_clone3, args, sizeof args);
}

static long sc_sigaltstack(const char *a)
{
	(void)a;
	stack_t old;
	return syscall(SYS_sigaltstack, NULL, &old);
}

static volatile sig_atomic_t handled;

static void on_usr1(int sig)
{
	(void)sig;
	handled = 1;
}

/* rt_sigaction, tgkill, and the handler returning through rt_sigreturn. */
static long sc_signal_handler_returns(const char *a)
{
	(void)a;
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_usr1;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR1, &sa, NULL) != 0)
		return -1;
	if (syscall(SYS_tgkill, (long)getpid(), syscall(SYS_gettid), (long)SIGUSR1) != 0)
		return -1;
	return handled ? 0 : -1;
}

static long sc_exit(const char *a)
{
	(void)a;
	exit(7);
}

static long sc_log_line(const char *a)
{
	(void)a;
	bst_log(BST_LOG_INFO, "sandbox probe: a line for the log");
	return 0;
}

static void aio_job(void *arg)
{
	(void)arg;
	bst_log(BST_LOG_INFO, "sandbox probe: aio res=0 errno=0");
}

static void aio_done(void *arg)
{
	(void)arg;
}

static long sc_aio(const char *a)
{
	(void)a;
	return bst_aio_submit(loop, aio_job, aio_done, NULL) == 0 ? -2 : -1; /* it logs for itself */
}

typedef struct probe {
	const char *name;
	long (*fn)(const char *arg);
} probe;

static const probe probes[] = {
	{ "execve", sc_execve },
	{ "ptrace", sc_ptrace },
	{ "socket_raw", sc_socket_raw },
	{ "socket_packet", sc_socket_packet },
	{ "socket_netlink", sc_socket_netlink },
	{ "socket_unix", sc_socket_unix },
	{ "socket_inet_raw_type", sc_socket_inet_raw_type },
	{ "socket_tcp", sc_socket_tcp },
	{ "socket_udp", sc_socket_udp },
	{ "bpf", sc_bpf },
	{ "mount", sc_mount },
	{ "memfd", sc_memfd },
	{ "open", sc_open },
	{ "read_file", sc_read_file },
	{ "write_file", sc_write_file },
	{ "mmap_exec", sc_mmap_exec },
	{ "mmap_rw", sc_mmap_rw },
	{ "mprotect_exec", sc_mprotect_exec },
	{ "prctl", sc_prctl },
	{ "dumpable", sc_dumpable },
	{ "ioctl_tiocsti", sc_ioctl_tiocsti },
	{ "fcntl_setown", sc_fcntl_setown },
	{ "fcntl_getfl", sc_fcntl_getfl },
	{ "setsockopt_ulp", sc_setsockopt_ulp },
	{ "futex_pi", sc_futex_pi },
	{ "futex_wait_1500ms", sc_futex_wait_1500ms },
	{ "tgkill_other", sc_tgkill_other },
	{ "tgkill_self", sc_tgkill_self },
	{ "kill", sc_kill },
	{ "setuid", sc_setuid },
	{ "chroot", sc_chroot },
	{ "unshare", sc_unshare },
	{ "seccomp", sc_seccomp },
	{ "io_uring_setup", sc_io_uring_setup },
	{ "accept4", sc_accept4 },
	{ "fork", sc_fork },
	{ "clone_thread", sc_clone_thread },
	{ "clone_vfork", sc_clone_vfork },
	{ "clone3", sc_clone3 },
	{ "sigaltstack", sc_sigaltstack },
	{ "signal_handler_returns", sc_signal_handler_returns },
	{ "exit", sc_exit },
	{ "log_line", sc_log_line },
	{ "aio", sc_aio },
};

/* Runs one probe. name is "<probe>" or "<probe>:<arg>". */
static void run_one(const char *name)
{
	char base[64];
	const char *colon = strchr(name, ':');
	const char *arg = colon != NULL ? colon + 1 : "";
	snprintf(base, sizeof base, "%.*s", (int)(colon != NULL ? colon - name : (long)strlen(name)),
		 name);
	for (size_t i = 0; i < sizeof probes / sizeof probes[0]; i++) {
		if (strcmp(probes[i].name, base) != 0)
			continue;
		errno = 0;
		long res = probes[i].fn(arg);
		if (res == -2)
			return; /* reports later, for itself */
		bst_log(BST_LOG_INFO, "sandbox probe: %s res=%ld errno=%d", name, res,
			res < 0 ? errno : 0);
		if (strcmp(base, "memfd") == 0)
			bst_log(BST_LOG_INFO, "sandbox probe: memfd_nr %ld", (long)SYS_memfd_create);
		return;
	}
	bst_log(BST_LOG_ERROR, "sandbox probe: no such probe: %s", name);
	abort();
}

static void pool_probe(void *arg)
{
	run_one(arg);
}

/* ---- the ring ---- */

static void run_uring(const char *name)
{
	int res;
	if (strcmp(name, "uring_socket") == 0) {
		res = bst_test_uring_op(loop, BST_TEST_URING_SOCKET);
	} else if (strcmp(name, "uring_nop") == 0) {
		res = bst_test_uring_op(loop, BST_TEST_URING_NOP);
	} else if (strcmp(name, "uring_register_restrictions") == 0) {
		res = bst_test_uring_op(loop, BST_TEST_URING_REG_RESTRICTIONS);
	} else if (strcmp(name, "uring_register_buffers") == 0) {
		res = bst_test_uring_op(loop, BST_TEST_URING_REG_BUFFERS);
	} else {
		static char buf[1 << 20];
		res = bst_test_uring_read(loop, cold_fd, buf, sizeof buf);
		unsigned long long sum = 0;
		for (int i = 0; i < res; i++)
			sum += (unsigned char)buf[i];
		bst_log(BST_LOG_INFO, "sandbox probe: uring_async_sum %llu", sum);
	}
	bst_log(BST_LOG_INFO, "sandbox probe: %s res=%d errno=0", name, res);
}

/* ---- the stages ---- */

/* First thing in a child, while it is still root in master's mount namespace. */
void bst_test_sandbox_claim(int slot)
{
	const char *v = getenv("BST_TEST_SANDBOX_PROBE");
	if (v == NULL)
		return;
	bool helper = strncmp(v, "helper:", 7) == 0;
	if (helper ? slot >= 0 : slot < 0 || atoi(v) != slot)
		return;
	const char *flag = getenv("BST_TEST_SANDBOX_PROBE_ONCE");
	if (flag != NULL && unlink(flag) != 0)
		return;
	snprintf(spec, sizeof spec, "%s", strchr(v, ':') + 1);
	fire = true;
}

/* Before the sandbox: what cannot be done from inside. */
void bst_test_sandbox_prepare(bst_loop *l)
{
	loop = l;
	const char *cold = fire ? strstr(spec, "uring_async:") : NULL;
	if (cold != NULL) {
		char path[512];
		snprintf(path, sizeof path, "%.*s", (int)strcspn(cold + 12, ","), cold + 12);
		cold_fd = open(path, O_RDONLY | O_CLOEXEC);
		/* A read the ring has to punt: no page of it is in memory. */
		if (cold_fd < 0 || fdatasync(cold_fd) != 0 ||
		    posix_fadvise(cold_fd, 0, 0, POSIX_FADV_DONTNEED) != 0)
			abort();
	}
}

static void for_each(bool ring)
{
	if (!fire)
		return;
	static char copy[1024];
	snprintf(copy, sizeof copy, "%s", spec);
	char *save = NULL;
	for (char *p = strtok_r(copy, ",", &save); p != NULL; p = strtok_r(NULL, ",", &save)) {
		if ((strncmp(p, "uring_", 6) == 0) != ring)
			continue;
		if (ring)
			run_uring(p);
		else if (strncmp(p, "pool:", 5) == 0)
			(void)bst_aio_submit(loop, pool_probe, aio_done, p + 5);
		else
			run_one(p);
	}
}

void bst_test_sandbox_probe_ring(void)
{
	for_each(true);
}

void bst_test_sandbox_probe(void)
{
	for_each(false);
}
#endif

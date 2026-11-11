/* The seccomp filter as data: the program built for each architecture and role, run in a small
 * classic-BPF interpreter against synthetic seccomp_data, on whatever this host is. x86_64 cannot
 * run here, and a table that is wrong for it fails only in production, so this is where it is
 * proved. The numbers are checked against pinned copies of the kernel's tables in
 * tests/fixtures/, not against this host's headers. */
#include "tap.h"

#include "proc/sandbox.h"
#include "proc/seccomp.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
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
#include <sys/socket.h>

#define KILL SECCOMP_RET_KILL_PROCESS
#define ALLOW SECCOMP_RET_ALLOW
#define LOG SECCOMP_RET_LOG
#define ERRNO(e) (SECCOMP_RET_ERRNO | (uint32_t)(e))
#define MAXINS 4096
#define PID 4242

/* ---- a classic BPF interpreter, seccomp's subset ---- */

static uint32_t run(const struct sock_filter *p, size_t n, const struct seccomp_data *d)
{
	uint32_t a = 0, x = 0, mem[16];
	memset(mem, 0, sizeof mem);
	for (size_t pc = 0; pc < n; pc++) {
		struct sock_filter f = p[pc];
		switch (f.code) {
		case BPF_LD | BPF_W | BPF_ABS:
			if (f.k % 4 != 0 || f.k + 4 > sizeof *d)
				goto bad;
			memcpy(&a, (const char *)d + f.k, 4);
			break;
		case BPF_LD | BPF_W | BPF_LEN: a = (uint32_t)sizeof *d; break;
		case BPF_LD | BPF_IMM: a = f.k; break;
		case BPF_LDX | BPF_IMM: x = f.k; break;
		case BPF_LD | BPF_MEM: a = mem[f.k]; break;
		case BPF_ST: mem[f.k] = a; break;
		case BPF_ALU | BPF_AND | BPF_K: a &= f.k; break;
		case BPF_ALU | BPF_AND | BPF_X: a &= x; break;
		case BPF_ALU | BPF_OR | BPF_K: a |= f.k; break;
		case BPF_ALU | BPF_RSH | BPF_K: a >>= f.k; break;
		case BPF_JMP | BPF_JA: pc += f.k; break;
		case BPF_JMP | BPF_JEQ | BPF_K: pc += a == f.k ? f.jt : f.jf; break;
		case BPF_JMP | BPF_JGE | BPF_K: pc += a >= f.k ? f.jt : f.jf; break;
		case BPF_JMP | BPF_JGT | BPF_K: pc += a > f.k ? f.jt : f.jf; break;
		case BPF_JMP | BPF_JSET | BPF_K: pc += (a & f.k) != 0 ? f.jt : f.jf; break;
		case BPF_RET | BPF_K: return f.k;
		default: goto bad;
		}
	}
bad:
	fprintf(stderr, "bad program at the instruction end or an unknown opcode\n");
	abort();
}

/* ---- pinned tables ---- */

typedef struct pin {
	char name[40];
	int nr;
	bool x32;
} pin;

static pin pins[1024];
static size_t npins;

/* tests/fixtures/syscall_<arch>.tbl: "<nr> <abi> <name> ...", as the kernel's own table. */
static void load_pins(const char *path)
{
	FILE *f = fopen(path, "r");
	if (f == NULL) {
		perror(path);
		abort();
	}
	char line[256];
	npins = 0;
	while (fgets(line, sizeof line, f) != NULL) {
		int nr;
		char abi[16], name[40];
		if (line[0] == '#' || sscanf(line, "%d %15s %39s", &nr, abi, name) != 3)
			continue;
		if (npins == sizeof pins / sizeof pins[0])
			abort();
		strcpy(pins[npins].name, name);
		pins[npins].nr = nr;
		pins[npins++].x32 = strcmp(abi, "x32") == 0;
	}
	fclose(f);
}

static int pinned(const char *name)
{
	for (size_t i = 0; i < npins; i++)
		if (!pins[i].x32 && strcmp(pins[i].name, name) == 0)
			return pins[i].nr;
	return -1;
}

/* ---- the program under test ---- */

typedef struct prog {
	struct sock_filter ins[MAXINS];
	size_t n;
	bst_seccomp_arch arch;
	bool x86;
} prog;

static prog *build(bst_seccomp_arch arch, bst_sandbox_role role, bst_seccomp_mode mode)
{
	static prog p;
	bst_seccomp_opts o = {.arch = arch, .role = role, .mode = mode, .self_pid = PID};
	long n = bst_seccomp_build(&o, p.ins, MAXINS);
	if (n <= 0)
		abort();
	p.n = (size_t)n;
	p.arch = arch;
	p.x86 = arch == BST_ARCH_X86_64;
	return &p;
}

static int nr_of(const prog *p, const char *name)
{
	load_pins(p->x86 ? "tests/fixtures/syscall_x86_64.tbl" : "tests/fixtures/syscall_aarch64.tbl");
	return pinned(name);
}

static uint32_t call(const prog *p, const char *name, uint64_t a0, uint64_t a1, uint64_t a2,
		     uint64_t a3)
{
	struct seccomp_data d;
	memset(&d, 0, sizeof d);
	int nr = nr_of(p, name);
	if (nr < 0) {
		fprintf(stderr, "%s has no number here\n", name);
		abort();
	}
	d.nr = nr;
	d.arch = p->x86 ? AUDIT_ARCH_X86_64 : AUDIT_ARCH_AARCH64;
	d.args[0] = a0;
	d.args[1] = a1;
	d.args[2] = a2;
	d.args[3] = a3;
	return run(p->ins, p->n, &d);
}

#define CALL0(p, name) call(p, name, 0, 0, 0, 0)

static const bst_seccomp_arch arches[] = {BST_ARCH_X86_64, BST_ARCH_AARCH64};
static const bst_sandbox_role roles[] = {BST_SANDBOX_WORKER, BST_SANDBOX_HELPER};

#define FOR_EACH_PROG(pvar)                                                        \
	for (size_t a_ = 0; a_ < 2; a_++)                                          \
		for (size_t r_ = 0; r_ < 2; r_++)                                  \
			for (prog *pvar = build(arches[a_], roles[r_], BST_SECCOMP_ON); \
			     pvar != NULL; pvar = NULL)

/* ---- the tables ---- */

TEST(every_entry_matches_the_pinned_tables)
{
	for (int a = 0; a < 2; a++) {
		bool x86 = arches[a] == BST_ARCH_X86_64;
		load_pins(x86 ? "tests/fixtures/syscall_x86_64.tbl"
			      : "tests/fixtures/syscall_aarch64.tbl");
		ASSERT(npins > 300);
		size_t n;
		const bst_sc_entry *t = bst_seccomp_table(&n);
		ASSERT(n > 10);
		for (size_t i = 0; i < n; i++) {
			int nr = x86 ? t[i].x86_64 : t[i].aarch64;
			int want = pinned(t[i].name);
			if (nr != want)
				fprintf(stderr, "%s on %s: table %d, pinned %d\n", t[i].name,
					x86 ? "x86_64" : "aarch64", nr, want);
			ASSERT_EQ(nr, want); /* -1 both ways: it does not exist there */
		}
	}
}

TEST(every_entry_exists_somewhere_and_has_a_reason)
{
	size_t n;
	const bst_sc_entry *t = bst_seccomp_table(&n);
	for (size_t i = 0; i < n; i++) {
		ASSERT(t[i].x86_64 >= 0 || t[i].aarch64 >= 0);
		ASSERT(t[i].roles != 0);
		ASSERT(t[i].why != NULL && strlen(t[i].why) >= 8);
		for (size_t k = 0; k < i; k++)
			ASSERT(strcmp(t[i].name, t[k].name) != 0);
	}
}

/* Never on any list, in any build. */
static const char *const banned[] = {
	"execve",     "execveat",  "ptrace",	"bpf",	      "mount",	     "umount2",
	"memfd_create", "pivot_root", "chroot", "setns",      "unshare",     "init_module",
	"finit_module", "kexec_load", "reboot", "process_vm_readv", "process_vm_writev",
	"userfaultfd", "perf_event_open", "keyctl", "add_key", "request_key",
	"io_uring_setup", "seccomp", "setuid", "setgid", "setgroups", "capset", "open_by_handle_at",
	"name_to_handle_at", "fanotify_init", "kill", "clone", "fork", "vfork", "symlink",
};

TEST(banned_syscalls_are_killed)
{
	FOR_EACH_PROG(p)
		for (size_t i = 0; i < sizeof banned / sizeof banned[0]; i++) {
			int nr = nr_of(p, banned[i]);
			if (nr < 0)
				continue; /* fork, vfork, symlink: x86_64 only */
			if (CALL0(p, banned[i]) != KILL)
				fprintf(stderr, "%s not killed\n", banned[i]);
			ASSERT_EQ(CALL0(p, banned[i]), KILL);
		}
}

TEST(no_table_row_names_a_banned_syscall)
{
	size_t n;
	const bst_sc_entry *t = bst_seccomp_table(&n);
	for (size_t i = 0; i < n; i++)
		for (size_t k = 0; k < sizeof banned / sizeof banned[0]; k++)
			ASSERT(strcmp(t[i].name, banned[k]) != 0);
}

/* ---- decisions ---- */

TEST(the_architecture_is_checked_first)
{
	FOR_EACH_PROG(p) {
		struct seccomp_data d;
		memset(&d, 0, sizeof d);
		d.nr = nr_of(p, "write");
		d.arch = p->x86 ? AUDIT_ARCH_AARCH64 : AUDIT_ARCH_X86_64;
		ASSERT_EQ(run(p->ins, p->n, &d), KILL);
		d.arch = AUDIT_ARCH_I386;
		ASSERT_EQ(run(p->ins, p->n, &d), KILL);
		d.arch = AUDIT_ARCH_ARM;
		ASSERT_EQ(run(p->ins, p->n, &d), KILL);
		d.arch = 0;
		ASSERT_EQ(run(p->ins, p->n, &d), KILL);
		d.arch = p->x86 ? AUDIT_ARCH_X86_64 : AUDIT_ARCH_AARCH64;
		ASSERT_EQ(run(p->ins, p->n, &d), ALLOW);
	}
	/* The first thing it does is load the architecture. */
	prog *p = build(BST_ARCH_X86_64, BST_SANDBOX_WORKER, BST_SECCOMP_ON);
	ASSERT_EQ(p->ins[0].code, BPF_LD | BPF_W | BPF_ABS);
	ASSERT_EQ(p->ins[0].k, offsetof(struct seccomp_data, arch));
}

#define X32_BIT 0x40000000u

TEST(x32_is_rejected_on_x86_64)
{
	for (int m = 0; m < 2; m++) {
		prog *p = build(BST_ARCH_X86_64, BST_SANDBOX_WORKER, m ? BST_SECCOMP_LOG : BST_SECCOMP_ON);
		struct seccomp_data d;
		memset(&d, 0, sizeof d);
		d.arch = AUDIT_ARCH_X86_64;
		d.nr = (int)(X32_BIT | (uint32_t)nr_of(p, "write"));
		ASSERT_EQ(run(p->ins, p->n, &d), KILL); /* `log` does not open the other ABI */
		d.nr = (int)(X32_BIT | 515u);		/* x32 readv */
		ASSERT_EQ(run(p->ins, p->n, &d), KILL);
		d.nr = (int)(X32_BIT | 0x3fffffffu);
		ASSERT_EQ(run(p->ins, p->n, &d), KILL);
		d.nr = -1;
		ASSERT_EQ(run(p->ins, p->n, &d), KILL);
		d.nr = nr_of(p, "write");
		ASSERT_EQ(run(p->ins, p->n, &d), ALLOW);
	}
}

TEST(aarch64_has_no_x32_gate_and_still_kills_the_bit)
{
	prog *p = build(BST_ARCH_AARCH64, BST_SANDBOX_WORKER, BST_SECCOMP_ON);
	struct seccomp_data d;
	memset(&d, 0, sizeof d);
	d.arch = AUDIT_ARCH_AARCH64;
	d.nr = (int)(X32_BIT | (uint32_t)nr_of(p, "write"));
	ASSERT_EQ(run(p->ins, p->n, &d), KILL);
}

TEST(clone3_answers_enosys)
{
	FOR_EACH_PROG(p)
		ASSERT_EQ(CALL0(p, "clone3"), ERRNO(ENOSYS));
	prog *p = build(BST_ARCH_AARCH64, BST_SANDBOX_WORKER, BST_SECCOMP_LOG);
	ASSERT_EQ(CALL0(p, "clone3"), ERRNO(ENOSYS));
}

TEST(clone_kills_threads_and_processes)
{
	const uint64_t thread = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
				CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
				CLONE_CHILD_CLEARTID;
	FOR_EACH_PROG(p) {
		ASSERT_EQ(call(p, "clone", thread, 0, 0, 0), KILL);
		ASSERT_EQ(call(p, "clone", SIGCHLD, 0, 0, 0), KILL);
		ASSERT_EQ(call(p, "clone", CLONE_VFORK | CLONE_VM | SIGCHLD, 0, 0, 0), KILL);
		ASSERT_EQ(call(p, "clone", 0, 0, 0, 0), KILL);
		ASSERT_EQ(call(p, "clone", (uint64_t)CLONE_NEWUSER, 0, 0, 0), KILL);
		ASSERT_EQ(call(p, "clone", 1ull << 32, 0, 0, 0), KILL);
	}
}

TEST(socket_by_domain_and_type)
{
	FOR_EACH_PROG(p) {
		if (p->arch == BST_ARCH_X86_64 && 0)
			continue;
		uint64_t stream = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
		ASSERT_EQ(call(p, "socket", AF_INET, SOCK_STREAM, 0, 0), ALLOW);
		ASSERT_EQ(call(p, "socket", AF_INET6, stream, 0, 0), ALLOW);
		ASSERT_EQ(call(p, "socket", AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0, 0), ALLOW);
		ASSERT_EQ(call(p, "socket", AF_INET, SOCK_RAW, IPPROTO_ICMP, 0), KILL);
		ASSERT_EQ(call(p, "socket", AF_INET6, SOCK_RAW | SOCK_CLOEXEC, 0, 0), KILL);
		ASSERT_EQ(call(p, "socket", AF_PACKET, SOCK_RAW, 0, 0), KILL);
		ASSERT_EQ(call(p, "socket", AF_PACKET, SOCK_DGRAM, 0, 0), KILL);
		ASSERT_EQ(call(p, "socket", AF_NETLINK, SOCK_DGRAM, 0, 0), KILL);
		ASSERT_EQ(call(p, "socket", AF_UNIX, SOCK_STREAM, 0, 0), KILL);
		ASSERT_EQ(call(p, "socket", AF_INET, SOCK_SEQPACKET, 0, 0), KILL);
		ASSERT_EQ(call(p, "socket", AF_INET, SOCK_PACKET, 0, 0), KILL);
	}
}

TEST(mmap_and_mprotect_never_execute)
{
	FOR_EACH_PROG(p) {
		ASSERT_EQ(call(p, "mmap", 0, 4096, PROT_READ | PROT_WRITE, 0), ALLOW);
		ASSERT_EQ(call(p, "mmap", 0, 4096, PROT_NONE, 0), ALLOW);
		ASSERT_EQ(call(p, "mmap", 0, 4096, PROT_READ | PROT_EXEC, 0), KILL);
		ASSERT_EQ(call(p, "mmap", 0, 4096, PROT_EXEC, 0), KILL);
		ASSERT_EQ(call(p, "mmap", 0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, 0), KILL);
		ASSERT_EQ(call(p, "mprotect", 0, 4096, PROT_READ, 0), ALLOW);
		ASSERT_EQ(call(p, "mprotect", 0, 4096, PROT_READ | PROT_EXEC, 0), KILL);
	}
}

TEST(fcntl_by_command)
{
	FOR_EACH_PROG(p) {
		ASSERT_EQ(call(p, "fcntl", 3, F_GETFL, 0, 0), ALLOW);
		ASSERT_EQ(call(p, "fcntl", 3, F_SETFL, O_NONBLOCK, 0), ALLOW);
		ASSERT_EQ(call(p, "fcntl", 3, F_DUPFD_CLOEXEC, 0, 0), ALLOW);
		ASSERT_EQ(call(p, "fcntl", 3, F_SETFD, FD_CLOEXEC, 0), ALLOW);
		ASSERT_EQ(call(p, "fcntl", 3, F_SETOWN, 1, 0), KILL);
		ASSERT_EQ(call(p, "fcntl", 3, F_SETSIG, 9, 0), KILL);
		ASSERT_EQ(call(p, "fcntl", 3, F_SETLEASE, 0, 0), KILL);
		ASSERT_EQ(call(p, "fcntl", 3, F_ADD_SEALS, 0, 0), KILL);
		ASSERT_EQ(call(p, "fcntl", 3, F_DUPFD, 0, 0), KILL);
	}
}

TEST(no_prctl_and_no_ioctl)
{
	FOR_EACH_PROG(p) {
		ASSERT_EQ(call(p, "prctl", 22 /* PR_SET_SECCOMP */, 0, 0, 0), KILL);
		ASSERT_EQ(call(p, "prctl", 3 /* PR_GET_DUMPABLE */, 0, 0, 0), KILL);
		ASSERT_EQ(call(p, "ioctl", 0, 0x5412 /* TIOCSTI */, 0, 0), KILL);
		ASSERT_EQ(call(p, "ioctl", 0, 0x5413 /* TIOCGWINSZ */, 0, 0), KILL);
	}
}

TEST(signals_go_to_this_process_alone)
{
	FOR_EACH_PROG(p) {
		ASSERT_EQ(call(p, "tgkill", PID, 7, SIGSEGV, 0), ALLOW);
		ASSERT_EQ(call(p, "tgkill", 1, 1, SIGKILL, 0), KILL);
		ASSERT_EQ(call(p, "tgkill", PID + 1, 7, SIGSEGV, 0), KILL);
		ASSERT_EQ(call(p, "tkill", 7, SIGABRT, 0, 0), ALLOW); /* musl's raise, abort only */
		ASSERT_EQ(call(p, "tkill", 7, SIGSEGV, 0, 0), KILL);
		ASSERT_EQ(call(p, "tkill", 1, SIGKILL, 0, 0), KILL);
	}
}

TEST(futex_has_no_priority_inheritance)
{
	FOR_EACH_PROG(p) {
		ASSERT_EQ(call(p, "futex", 0, FUTEX_WAIT, 0, 0), ALLOW);
		ASSERT_EQ(call(p, "futex", 0, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0), ALLOW);
		ASSERT_EQ(call(p, "futex", 0, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG |
				   FUTEX_CLOCK_REALTIME, 0, 0), ALLOW);
		ASSERT_EQ(call(p, "futex", 0, FUTEX_LOCK_PI, 0, 0), KILL);
		ASSERT_EQ(call(p, "futex", 0, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0), KILL);
		ASSERT_EQ(call(p, "futex", 0, FUTEX_CMP_REQUEUE_PI, 0, 0), KILL);
		ASSERT_EQ(call(p, "futex", 0, FUTEX_WAIT_REQUEUE_PI, 0, 0), KILL);
	}
}

TEST(setsockopt_is_what_accepted_sockets_need)
{
	FOR_EACH_PROG(p) {
		if (roles[r_] != BST_SANDBOX_WORKER)
			continue;
		ASSERT_EQ(call(p, "setsockopt", 3, IPPROTO_TCP, TCP_QUICKACK, 0), ALLOW);
		/* kernel TLS (Phase 6): OpenSSL's own TCP_ULP and SOL_TLS TLS_TX/TLS_RX */
		ASSERT_EQ(call(p, "setsockopt", 3, IPPROTO_TCP, 31 /* TCP_ULP */, 0), ALLOW);
		ASSERT_EQ(call(p, "setsockopt", 3, 282 /* SOL_TLS */, 1 /* TLS_TX */, 0), ALLOW);
		ASSERT_EQ(call(p, "setsockopt", 3, 282, 2 /* TLS_RX */, 0), ALLOW);
		ASSERT_EQ(call(p, "setsockopt", 3, IPPROTO_TCP, TCP_CONGESTION, 0), KILL);
		ASSERT_EQ(call(p, "setsockopt", 3, 282, 3, 0), KILL);
		ASSERT_EQ(call(p, "setsockopt", 3, SOL_SOCKET, SO_ATTACH_FILTER, 0), KILL);
	}
}

TEST(connect_is_the_helpers_for_ocsp)
{
	/* The helper fetches OCSP responses over the epoll loop (tests/integration/test_ocsp.py runs it
	 * without sanitizers: the fetch dies without this row); a worker never connects. */
	for (size_t a = 0; a < 2; a++) {
		prog *p = build(arches[a], BST_SANDBOX_HELPER, BST_SECCOMP_ON); /* build reuses its buffer */
		ASSERT_EQ(call(p, "connect", 3, 0, 16, 0), ALLOW);
		p = build(arches[a], BST_SANDBOX_WORKER, BST_SECCOMP_ON);
		ASSERT_EQ(call(p, "connect", 3, 0, 16, 0), KILL);
	}
}

TEST(roles_differ)
{
	for (size_t a = 0; a < 2; a++) {
		prog *p = build(arches[a], BST_SANDBOX_WORKER, BST_SECCOMP_ON);
		ASSERT_EQ(call(p, "accept4", 3, 0, 0, 0), ALLOW);
		p = build(arches[a], BST_SANDBOX_HELPER, BST_SECCOMP_ON);
		ASSERT_EQ(call(p, "accept4", 3, 0, 0, 0), KILL);
	}
}

TEST(what_the_crash_handler_and_the_log_need)
{
	static const char *const need[] = {
		"write", "read",	 "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
		"rt_sigpending", "rt_sigtimedwait", "getpid", "gettid",	"exit_group",
		"sigaltstack", "splice", "sendto",	 "recvfrom",	   "accept4",
		"clock_gettime", "getrandom", "io_uring_enter", "epoll_ctl", "epoll_pwait",
		"restart_syscall",
	};
	for (size_t a = 0; a < 2; a++) {
		prog *p = build(arches[a], BST_SANDBOX_WORKER, BST_SECCOMP_ON);
		for (size_t i = 0; i < sizeof need / sizeof need[0]; i++) {
			if (CALL0(p, need[i]) != ALLOW)
				fprintf(stderr, "%s not allowed\n", need[i]);
			ASSERT_EQ(CALL0(p, need[i]), ALLOW);
		}
	}
}

TEST(the_two_arches_differ_where_the_abi_does)
{
	/* x86_64 libcs reach these under their own numbers, which aarch64 does not even have. */
	prog *p = build(BST_ARCH_X86_64, BST_SANDBOX_WORKER, BST_SECCOMP_ON);
	ASSERT_EQ(CALL0(p, "epoll_wait"), ALLOW);
	p = build(BST_ARCH_AARCH64, BST_SANDBOX_WORKER, BST_SECCOMP_ON);
	ASSERT_EQ(nr_of(p, "epoll_wait"), -1);
}

TEST(log_mode_logs_what_on_would_kill)
{
	for (size_t a = 0; a < 2; a++) {
		prog *p = build(arches[a], BST_SANDBOX_WORKER, BST_SECCOMP_LOG);
		ASSERT_EQ(CALL0(p, "execve"), LOG);
		ASSERT_EQ(call(p, "socket", AF_INET, SOCK_RAW, 0, 0), LOG);
		ASSERT_EQ(call(p, "mmap", 0, 4096, PROT_EXEC, 0), LOG);
		ASSERT_EQ(CALL0(p, "write"), ALLOW);
		struct seccomp_data d;
		memset(&d, 0, sizeof d);
		d.nr = nr_of(p, "write");
		d.arch = p->x86 ? AUDIT_ARCH_AARCH64 : AUDIT_ARCH_X86_64;
		ASSERT_EQ(run(p->ins, p->n, &d), KILL); /* a foreign ABI is never a list question */
	}
}

TEST(a_full_program_is_within_every_limit)
{
	FOR_EACH_PROG(p) {
		ASSERT(p->n <= BPF_MAXINSNS);
		ASSERT(p->n >= 20);
		ASSERT_EQ(p->ins[p->n - 1].code, BPF_RET | BPF_K);
		for (size_t i = 0; i < p->n; i++) {
			struct sock_filter f = p->ins[i];
			if (BPF_CLASS(f.code) == BPF_JMP && BPF_OP(f.code) != BPF_JA) {
				ASSERT(i + 1 + f.jt < p->n);
				ASSERT(i + 1 + f.jf < p->n);
			}
		}
	}
	bst_seccomp_opts o = {.arch = BST_ARCH_AARCH64, .role = BST_SANDBOX_WORKER,
			      .mode = BST_SECCOMP_ON, .self_pid = PID};
	struct sock_filter small[8];
	ASSERT_EQ(bst_seccomp_build(&o, small, 8), -ENOSPC);
}

TEST(allowed_list_names_every_allowed_syscall)
{
	/* What `make check-release` reads: the binary's own list, by name. */
	char buf[8192];
	size_t n = bst_seccomp_list(BST_ARCH_X86_64, BST_SANDBOX_WORKER, buf, sizeof buf);
	ASSERT(n > 0 && n < sizeof buf);
	ASSERT(strstr(buf, "\nwrite\n") != NULL);
	ASSERT(strstr(buf, "\nexecve\n") == NULL);
	ASSERT(strstr(buf, "\nepoll_wait\n") != NULL);
	n = bst_seccomp_list(BST_ARCH_AARCH64, BST_SANDBOX_WORKER, buf, sizeof buf);
	ASSERT(strstr(buf, "\nepoll_wait\n") == NULL);
}

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define ASAN_BUILD 1
#endif
#endif

TEST(sanitizer_additions_exist_only_in_sanitizer_builds)
{
	size_t n;
	const bst_sc_entry *t = bst_seccomp_table(&n);
	bool any = false;
	for (size_t i = 0; i < n; i++)
		any |= t[i].sanitizer_only;
#ifdef ASAN_BUILD
	ASSERT(any);
#else
	ASSERT(!any);
#endif
}

TEST(what_sanitizer_rows_may_do)
{
	size_t n;
	const bst_sc_entry *t = bst_seccomp_table(&n);
	/* Each only answers an errno: none lets a call run, so the kill tests hold in this build. */
	for (size_t i = 0; i < n; i++)
		if (t[i].sanitizer_only)
			ASSERT(t[i].fail_errno != 0);
	for (size_t a = 0; a < 2; a++) {
		prog *p = build(arches[a], BST_SANDBOX_WORKER, BST_SECCOMP_LOG);
		ASSERT_EQ(call(p, "openat", 0, 0, 0, 0), LOG); /* and under `log` they are out of the way */
		p = build(arches[a], BST_SANDBOX_WORKER, BST_SECCOMP_ON);
#ifdef ASAN_BUILD
		ASSERT_EQ(call(p, "openat", 0, 0, 0, 0), ERRNO(ENOENT));
		ASSERT_EQ(call(p, "ioctl", 0, 0x5401 /* TCGETS */, 0, 0), ERRNO(ENOTTY));
#else
		ASSERT_EQ(call(p, "openat", 0, 0, 0, 0), KILL);
		ASSERT_EQ(call(p, "ioctl", 0, 0x5401 /* TCGETS */, 0, 0), KILL);
#endif
	}
}

TAP_MAIN()

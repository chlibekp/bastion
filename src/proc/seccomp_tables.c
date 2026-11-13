/* The syscall allowlist. Data only: seccomp.c turns it into a filter. A row: the name, its numbers
 * on x86_64 and aarch64 (-1 where the architecture has no such call; test_seccomp checks both
 * against the kernel's own tables, pinned in tests/fixtures/), who may call it, and why it is
 * here. Most frequent first, because the filter tests in this order.
 *
 * The rule (README Global Constraints): this is the shortest list that lets every test pass. A new
 * row needs a test that fails without it and a reason in its `why`. scripts/seccomp-minimality.sh
 * removes each row in turn and reports the ones nothing fails for. x86_64 rows with no aarch64
 * number cannot be proved here: they are the same call under the name x86_64 libcs use.
 *
 * Absent on purpose: execve, ptrace, bpf, mount, memfd_create, clone, fork, anything that opens a
 * file (until a phase serves one), prctl, ioctl. Phase 5 adds file calls with its tests. */
#include "proc/seccomp.h"

#include <asm/ioctls.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>

#define WK BST_SC_WORKER
#define ALL BST_SC_ROLES

#define CONDS(c) .conds = (c), .nconds = sizeof(c) / sizeof((c)[0])
#define ROW(n, x, a, r, reason, ...) \
	{ .name = (n), .x86_64 = (x), .aarch64 = (a), .roles = (r), .why = (reason), __VA_ARGS__ }

static const bst_sc_cond no_exec_prot[] = {
	{ .test = BST_SC_NO_BITS, .arg = 2, .mask = PROT_EXEC },
};
static const bst_sc_cond safe_futex[] = {
	{ .test = BST_SC_IN, .arg = 1, .mask = (uint32_t)~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME),
	  .nvals = 6,
	  .vals = { FUTEX_WAIT, FUTEX_WAKE, FUTEX_REQUEUE, FUTEX_CMP_REQUEUE, FUTEX_WAIT_BITSET,
		    FUTEX_WAKE_BITSET } },
};
static const bst_sc_cond inet_socket[] = {
	{ .test = BST_SC_IN, .arg = 0, .mask = UINT32_MAX, .nvals = 2, .vals = { AF_INET, AF_INET6 } },
	{ .test = BST_SC_IN, .arg = 1, .mask = 0xf, .nvals = 2, .vals = { SOCK_STREAM, SOCK_DGRAM } },
};
static const bst_sc_cond own_process[] = {
	{ .test = BST_SC_IS_SELF, .arg = 0 },
};
static const bst_sc_cond abort_only[] = {
	{ .test = BST_SC_IN, .arg = 1, .mask = UINT32_MAX, .nvals = 1, .vals = { SIGABRT } },
};
static const bst_sc_cond plain_fcntl[] = {
	{ .test = BST_SC_IN, .arg = 1, .mask = UINT32_MAX, .nvals = 6,
	  .vals = { F_GETFL, F_SETFL, F_DUPFD_CLOEXEC, F_SETFD, F_SETPIPE_SZ, F_GETPIPE_SZ } },
};
/* TCP_QUICKACK, and what OpenSSL sets itself when it moves a connection's record layer to the
 * kernel (tls/ktls.c): TCP_ULP "tls", then SOL_TLS TLS_TX (1) and TLS_RX (2). The filter tests the
 * level and the option separately, so IPPROTO_TCP with option 1 or 2 (TCP_NODELAY, TCP_MAXSEG)
 * and SOL_TLS with TCP_QUICKACK also pass: harmless tuning, no data or privilege. */
static const bst_sc_cond tcp_tuning[] = {
	{ .test = BST_SC_IN, .arg = 1, .mask = UINT32_MAX, .nvals = 2, .vals = { IPPROTO_TCP, 282 } },
	{ .test = BST_SC_IN, .arg = 2, .mask = UINT32_MAX, .nvals = 4, .vals = { TCP_QUICKACK, 31, 1, 2 } },
};

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
static const bst_sc_cond isatty_only[] = {
	{ .test = BST_SC_IN, .arg = 1, .mask = UINT32_MAX, .nvals = 1, .vals = { TCGETS } },
};
#endif
#endif

static const bst_sc_entry table[] = {
	/* the loop */
	ROW("io_uring_enter", 426, 426, ALL, "submits and waits on the ring made before the sandbox"),
	ROW("epoll_pwait", 281, 22, ALL, "the epoll loop's wait, and musl's epoll_wait"),
	ROW("epoll_wait", 232, -1, ALL, "glibc's epoll_wait on x86_64"),
	ROW("epoll_ctl", 233, 21, ALL, "arms sockets on the epoll loop"),
	ROW("clock_gettime", 228, 113, ALL, "log prefix and loop time when the vDSO cannot serve it"),
	/* sockets */
	ROW("recvfrom", 45, 207, ALL, "the channel, and connections on the epoll loop"),
	ROW("sendto", 44, 206, ALL, "a socket as error log"),
	ROW("sendmsg", 46, 211, ALL, "the channel, and connections on the epoll loop"),
	ROW("recvmsg", 47, 212, ALL, "the channel and UDP on the epoll loop"),
	ROW("recvmmsg", 299, 243, WK, "QUIC datagrams in batches on the readiness path (io/udp.c)"),
	ROW("sendmmsg", 307, 269, WK, "QUIC packets in batches on the epoll loop (io/udp_send.c)"),
	ROW("accept4", 288, 242, WK, "the epoll loop, the io_uring sweep, a stopping worker's drain"),
	ROW("getpeername", 52, 205, WK, "the peer of a connection io_uring accepted"),
	ROW("getsockname", 51, 204, WK, "the address a client connected to, for a PROXY protocol header sent upstream"),
	ROW("getsockopt", 55, 209, ALL, "SO_ERROR after a failed or completed socket operation"),
	ROW("setsockopt", 54, 208, WK, "TCP_QUICKACK on accepted sockets; TCP_ULP and SOL_TLS TLS_TX/TLS_RX when OpenSSL moves a connection to kernel TLS (ktls)",
	    CONDS(tcp_tuning)),
	ROW("connect", 42, 203, ALL, "the helper's OCSP fetch and DNS queries, and a worker's upstream "
				     "connections (proxy/pool.c) on the epoll loop; io_uring connects "
				     "through the ring"),
	ROW("shutdown", 48, 210, ALL, "closing a socket that io_uring still holds"),
	ROW("socket", 41, 198, ALL, "outbound TCP and UDP only: no raw, packet, netlink or unix socket",
	    CONDS(inet_socket)),
	ROW("fcntl", 72, 25, ALL, "O_NONBLOCK on wrapped sockets; F_DUPFD_CLOEXEC takes back the reserved "
					"descriptors after an EMFILE shed (a duplicate of an fd it already has), "
					"F_SETFD because musl follows that with FD_CLOEXEC, and F_SETPIPE_SZ/F_GETPIPE_SZ "
					"to size the pipes io_uring splices file segments through",
	    CONDS(plain_fcntl)),
	/* files and memory */
	ROW("read", 0, 63, ALL, "the crash handler's probe pipe, the log's splice pipe, eventfd"),
	ROW("write", 1, 64, ALL, "log lines, eventfd wakes, the crash handler's probe pipe"),
	ROW("close", 3, 57, ALL, "connections end"),
	ROW("splice", 275, 76, ALL, "log lines into a pipe this user may not reopen"),
	/* serving files (Phase 5): the root is opened before the sandbox, a request opens below it */
	ROW("openat2", 437, 437, WK, "opens a served file relative to the root's descriptor, "
				      "RESOLVE_BENEATH: the only call that names a path"),
	ROW("statx", 332, 291, WK, "size, type and mtime of the file just opened (AT_EMPTY_PATH: an fd)"),
	ROW("fstat", 5, 80, WK, "the file's device and size before the readahead probe (net_common.c)"),
	ROW("pipe2", 293, 59, WK, "the pipes io_uring splices file segments through (uring_bufs.c)"),
	ROW("sendfile", 40, 71, WK, "file segments to a socket where splice is not used"),
	ROW("getdents64", 217, 61, WK, "`autoindex`: the aio pool lists a directory in batches"),
	ROW("pread64", 17, 67, WK, "`sendfile off`: the aio pool reads a file chunk to send it"),
	ROW("pwrite64", 18, 68, WK, "spooled request and response bodies into an unnamed temp file (proxy/spool.c)"),
	ROW("preadv2", 327, 286, WK, "RWF_NOWAIT probe: are a file's pages in the cache"),
	ROW("readahead", 187, 213, WK, "starts the disk read of a cold file range on the aio pool"),
	ROW("mmap", 9, 222, ALL, "malloc, never executable", CONDS(no_exec_prot)),
	ROW("mprotect", 10, 226, ALL, "malloc arenas, never executable", CONDS(no_exec_prot)),
	ROW("munmap", 11, 215, ALL, "free of large blocks"),
	ROW("mremap", 25, 216, ALL, "realloc of large blocks"),
	ROW("madvise", 28, 233, ALL, "malloc gives pages back"),
	ROW("brk", 12, 214, ALL, "malloc on glibc"),
	ROW("futex", 202, 98, ALL, "the aio pool's locks; priority inheritance is refused",
	    CONDS(safe_futex)),
	ROW("getrandom", 318, 278, ALL, "JSON key seeds, OpenSSL, mimalloc"),
	ROW("sched_yield", 24, 124, ALL, "the bounded SQPOLL wait"),
	/* signals, the log and the crash handler */
	ROW("rt_sigprocmask", 14, 135, ALL, "the log blocks SIGPIPE around each write"),
	ROW("rt_sigpending", 127, 136, ALL, "the log: was SIGPIPE pending already"),
	ROW("rt_sigtimedwait", 128, 137, ALL, "the log consumes the SIGPIPE its own write raised"),
	ROW("rt_sigaction", 13, 134, ALL, "the crash handler restores the default before re-raising"),
	ROW("rt_sigreturn", 15, 139, ALL, "a signal handler returning"),
	ROW("sigaltstack", 131, 132, ALL, "ASan reads it on every noreturn call; thread exit restores"),
	ROW("getpid", 39, 172, ALL, "the pid in each log line, and tgkill"),
	ROW("gettid", 186, 178, ALL, "the crash handler's re-raise, and libc's raise"),
	ROW("tgkill", 234, 131, ALL, "the crash handler's re-raise and glibc's abort, this process only",
	    CONDS(own_process)),
	ROW("tkill", 200, 130, ALL, "musl's abort, SIGABRT only", CONDS(abort_only)),
	ROW("restart_syscall", 219, 128, ALL, "a timed wait resuming after SIGSTOP and SIGCONT"),
	ROW("exit_group", 231, 94, ALL, "every way out"),
	/* never allowed, never fatal */
	ROW("clone3", 435, 435, ALL, "its flags are behind a pointer: ENOSYS sends libc to clone",
	    .fail_errno = ENOSYS),
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define BST_SAN_ROW(n, x, a, reason, ...) \
	ROW(n, x, a, ALL, reason, .sanitizer_only = true, __VA_ARGS__)
	/* ASan looks for its symbolizer before forking one: not found ends that at once. */
	BST_SAN_ROW("newfstatat", 262, 79, "ASan's symbolizer check gets ENOENT, so it never forks",
		    .fail_errno = ENOENT),
	BST_SAN_ROW("stat", 4, -1, "the same check under x86_64's number", .fail_errno = ENOENT),
	BST_SAN_ROW("openat", 257, 56, "ASan reads /proc on its way through a report: it hears ENOENT",
		    .fail_errno = ENOENT),
	BST_SAN_ROW("open", 2, -1, "the same read under x86_64's number", .fail_errno = ENOENT),
	BST_SAN_ROW("ioctl", 16, 29, "ASan asks if its report file is a tty: it hears no",
		    .fail_errno = ENOTTY, CONDS(isatty_only)),
#endif
#endif
};

const bst_sc_entry *bst_seccomp_table(size_t *n)
{
	*n = sizeof table / sizeof table[0];
	return table;
}

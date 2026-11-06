/* See signals.h. */
#include "proc/signals.h"

#include "core/log.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define NO_SAN __attribute__((no_sanitize("address", "undefined", "thread")))

static const int master_sigs[] = { SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGUSR2, SIGCHLD };
static const int child_ignored[] = { SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGUSR2 };
static const int fatal_sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT };

int bst_signals_master(void)
{
	sigset_t set;
	sigemptyset(&set);
	for (size_t i = 0; i < sizeof master_sigs / sizeof master_sigs[0]; i++)
		sigaddset(&set, master_sigs[i]);
	if (sigprocmask(SIG_BLOCK, &set, NULL) != 0)
		return -1;
	return signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
}

void bst_signals_child(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	for (size_t i = 0; i < sizeof child_ignored / sizeof child_ignored[0]; i++)
		sigaction(child_ignored[i], &sa, NULL);
	sa.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa, NULL);
	sigset_t none;
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
}

/* ---- the walk ---- */

static int probe[2] = { -1, -1 };

void bst_crash_init_walk(void)
{
	if (probe[0] < 0 && pipe2(probe, O_CLOEXEC | O_NONBLOCK) != 0)
		probe[0] = probe[1] = -1;
}

/* Copies n bytes from addr, or fails, without ever loading from addr in user space: the kernel
 * reads it for write(2) and answers EFAULT. Raw syscalls, so no sanitizer interceptor checks
 * the address first. */
static NO_SAN bool safe_read(uintptr_t addr, void *out, size_t n)
{
	if (probe[1] < 0)
		return false;
	long w = syscall(SYS_write, probe[1], (const void *)addr, n);
	if (w <= 0)
		return false;
	long r = syscall(SYS_read, probe[0], out, (size_t)w); /* a short copy still empties the pipe */
	return w == (long)n && r == w;
}

NO_SAN size_t bst_crash_walk_(uintptr_t fp, uintptr_t *out, size_t max)
{
	size_t n = 0;
	while (n < max) {
		uintptr_t frame[2]; /* the caller's frame pointer, then the return address */
		if (fp == 0 || (fp & (sizeof(uintptr_t) - 1)) != 0 ||
		    !safe_read(fp, frame, sizeof frame))
			break;
		if (frame[1] == 0)
			break;
		out[n++] = frame[1];
		/* The stack grows down, so a caller's frame is higher and not absurdly far. */
		if (frame[0] <= fp || frame[0] - fp > BST_CRASH_MAX_FRAME)
			break;
		fp = frame[0];
	}
	return n;
}

/* ---- the handler ---- */

NO_SAN size_t bst_crash_fmt_hex_(char *b, uint64_t v)
{
	static const char hex[] = "0123456789abcdef";
	size_t n = 0;
	b[n++] = '0';
	b[n++] = 'x';
	int shift = 60;
	while (shift > 0 && (v >> shift) == 0)
		shift -= 4;
	for (; shift >= 0; shift -= 4)
		b[n++] = hex[(v >> shift) & 15];
	b[n] = '\0';
	return n;
}

NO_SAN size_t bst_crash_fmt_dec_(char *b, uint64_t v)
{
	char tmp[20];
	size_t k = 0, n = 0;
	do {
		tmp[k++] = (char)('0' + v % 10);
		v /= 10;
	} while (v != 0);
	while (k > 0)
		b[n++] = tmp[--k];
	b[n] = '\0';
	return n;
}

typedef struct line {
	char b[120];
	size_t n;
} line;

static NO_SAN void put_s(line *l, const char *s)
{
	while (*s != '\0' && l->n < sizeof l->b)
		l->b[l->n++] = *s++;
}

static NO_SAN void put_dec(line *l, uint64_t v)
{
	char d[21];
	bst_crash_fmt_dec_(d, v);
	put_s(l, d);
}

static NO_SAN void put_hex(line *l, uint64_t v)
{
	char d[21];
	bst_crash_fmt_hex_(d, v);
	put_s(l, d);
}

static NO_SAN void frame_line(unsigned i, uintptr_t addr)
{
	line l = { .n = 0 };
	put_s(&l, "crash: #");
	put_dec(&l, i);
	put_s(&l, " ");
	put_hex(&l, addr);
	bst_log_safe_line(BST_LOG_ERROR, l.b, l.n);
}

static NO_SAN void context_regs(const void *ucv, uintptr_t *pc, uintptr_t *fp, uintptr_t *lr)
{
	const ucontext_t *uc = ucv;
	*pc = *fp = *lr = 0;
#if defined(__x86_64__)
	*pc = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
	*fp = (uintptr_t)uc->uc_mcontext.gregs[REG_RBP];
#elif defined(__aarch64__)
	*pc = (uintptr_t)uc->uc_mcontext.pc;
	*fp = (uintptr_t)uc->uc_mcontext.regs[29];
	*lr = (uintptr_t)uc->uc_mcontext.regs[30];
#else
#error "crash handler: add this architecture's pc and frame pointer"
#endif
}

/* Default disposition, then the signal again: the parent sees the real death. SA_NODEFER keeps
 * it unblocked. _exit only if the signal somehow did not kill. */
static NO_SAN void reraise(int sig)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sigaction(sig, &sa, NULL);
	raise(sig);
	_exit(128 + sig);
}

static atomic_flag in_handler = ATOMIC_FLAG_INIT;

static NO_SAN void crash_handler(int sig, siginfo_t *si, void *uc)
{
	if (atomic_flag_test_and_set(&in_handler)) /* another thread is reporting */
		reraise(sig);
	uintptr_t pc, fp, lr;
	context_regs(uc, &pc, &fp, &lr);

	line l = { .n = 0 };
	put_s(&l, "crash: signal ");
	put_dec(&l, (uint64_t)sig);
	put_s(&l, " code ");
	put_dec(&l, (uint64_t)(unsigned)si->si_code);
	put_s(&l, " addr ");
	put_hex(&l, (uint64_t)(uintptr_t)si->si_addr);
	bst_log_safe_line(BST_LOG_ERROR, l.b, l.n);

	l.n = 0;
	put_s(&l, "crash: anchor bst_crash_install ");
	put_hex(&l, (uint64_t)(uintptr_t)bst_crash_install);
	bst_log_safe_line(BST_LOG_ERROR, l.b, l.n);

	unsigned i = 0;
	frame_line(i++, pc);
	if (lr != 0)
		frame_line(i++, lr);
	uintptr_t addrs[BST_CRASH_FRAMES];
	size_t n = bst_crash_walk_(fp, addrs, BST_CRASH_FRAMES);
	for (size_t k = 0; k < n; k++)
		frame_line(i++, addrs[k]);
	bst_log_safe_line(BST_LOG_ERROR, "crash: end", 10);
	reraise(sig);
}

void bst_crash_install(void)
{
	/* A forked child gets a pipe of its own: siblings crashing at once must not share one. */
	if (probe[0] >= 0) {
		close(probe[0]);
		close(probe[1]);
		probe[0] = probe[1] = -1;
	}
	bst_crash_init_walk();
	void *stk = mmap(NULL, BST_CRASH_ALTSTACK, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stk == MAP_FAILED) {
		bst_log(BST_LOG_WARN, "crash handler: no alternate stack: %s", strerror(errno));
		return;
	}
	stack_t ss = { .ss_sp = stk, .ss_size = BST_CRASH_ALTSTACK, .ss_flags = 0 };
	if (sigaltstack(&ss, NULL) != 0) {
		bst_log(BST_LOG_WARN, "crash handler: sigaltstack: %s", strerror(errno));
		munmap(stk, BST_CRASH_ALTSTACK);
		return;
	}
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = crash_handler;
	sa.sa_flags = (int)(SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESETHAND);
	sigemptyset(&sa.sa_mask);
	for (size_t i = 0; i < sizeof fatal_sigs / sizeof fatal_sigs[0]; i++)
		sigaction(fatal_sigs[i], &sa, NULL);
}

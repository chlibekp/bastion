/* Signal handling for every process: master's signalfd, a child's reset, and the crash handler. */
#ifndef BST_PROC_SIGNALS_H
#define BST_PROC_SIGNALS_H

#include <stddef.h>
#include <stdint.h>

#define BST_CRASH_FRAMES 64u               /* return addresses written, at most */
#define BST_CRASH_MAX_FRAME ((uintptr_t)8 << 20) /* a larger step between frames ends the walk */
#define BST_CRASH_ALTSTACK ((size_t)64 << 10)

/* Blocks the signals master handles and returns a non-blocking, close-on-exec signalfd for
 * them (TERM, INT, QUIT, HUP, USR2, CHLD). -1 with errno set. */
int bst_signals_master(void);

/* In a forked child: workers and the helper take orders over the channel, so the signals a
 * terminal or a process-group kill sends to everyone are ignored here (master handles them and
 * tells its children), and nothing stays blocked. */
void bst_signals_child(void);

/* Installs the crash handler for SIGSEGV, SIGBUS, SIGILL, SIGFPE and SIGABRT, on an alternate
 * stack of its own, so a stack overflow is caught. It writes the signal, the faulting address
 * and return addresses to the error log, then re-raises with the default disposition, so the
 * parent sees the real signal.
 *
 * The handler uses async-signal-safe calls only. The return addresses come from a frame-pointer
 * walk (musl has no execinfo; every build has -fno-omit-frame-pointer), and each frame is read
 * through a private pipe: write(2) of a bad address fails with EFAULT, where a load would fault
 * inside the handler. The walk is bounded, and frames must rise through the stack.
 *
 * The first line after the signal gives the running address of bst_crash_install, so a return
 * address can be turned into a symbol: addr - anchor + `nm bastion | grep bst_crash_install`.
 *
 * sigaltstack and the signal mask are per thread: this covers the calling thread, and aio pool
 * threads set up both for themselves (io/aio.c), since they run all disk and CPU-heavy work. */
void bst_crash_install(void);

/* The pipe bst_crash_walk_ reads through. bst_crash_install calls it; tests call it directly. */
void bst_crash_init_walk(void);

/* Walks saved frame pointers from fp, writing return addresses to out. Returns how many.
 * Async-signal-safe, and safe on any fp. */
size_t bst_crash_walk_(uintptr_t fp, uintptr_t *out, size_t max);

/* NUL-terminated digits in b (at least 21 bytes); return the length. */
size_t bst_crash_fmt_hex_(char *b, uint64_t v);
size_t bst_crash_fmt_dec_(char *b, uint64_t v);

#endif

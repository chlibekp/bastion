/* See test_hooks.h. */
#ifdef BST_TEST
#include "proc/test_hooks.h"

#include "core/alloc.h"
#include "core/log.h"
#include "io/aio.h"
#include "io/net.h"
#include "proc/channel.h"

#include <mimalloc.h>
#include <openssl/crypto.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* "<slot|helper>:<rest>" for this child: rest, or NULL. */
static const char *for_slot(const char *var, int slot)
{
	const char *v = getenv(var);
	if (v == NULL)
		return NULL;
	const char *colon = strchr(v, ':');
	if (colon == NULL)
		return NULL;
	if (strncmp(v, "helper:", 7) == 0)
		return slot < 0 ? colon + 1 : NULL;
	return slot >= 0 && atoi(v) == slot ? colon + 1 : NULL;
}

static long loop_euid = -1;

void bst_test_child_loop(int slot)
{
	loop_euid = (long)geteuid();
	const char *d = getenv("BST_TEST_HELPER_DELAY_MS");
	if (slot < 0 && d != NULL) {
		long ms = atol(d);
		struct timespec ts = {ms / 1000, (ms % 1000) * 1000000};
		nanosleep(&ts, NULL);
	}
	const char *spec = for_slot("BST_TEST_WORKER_URING_FAIL", slot);
	if (spec != NULL)
		setenv("BST_TEST_URING_FAIL", spec, 1);
}

bool bst_test_child_watch(void)
{
	const char *d = getenv("BST_TEST_WORKER_WATCH_DELAY_MS");
	if (d != NULL) {
		long ms = atol(d);
		struct timespec ts = {ms / 1000, (ms % 1000) * 1000000};
		nanosleep(&ts, NULL);
	}
	return getenv("BST_TEST_NO_PDEATHSIG") == NULL;
}

static __attribute__((noinline)) int overflow(int n)
{
	volatile char pad[4096];
	pad[0] = (char)n;
	if (n < 0) /* never: only here to give the recursion an end the compiler can see */
		return 0;
	return overflow(n + 1) + pad[0];
}

/* The frame pointer is garbage when the fault happens, so the walk starts from it. */
static __attribute__((noinline)) void fault_with_wild_frame_pointer(void)
{
	unsigned long wild = 0xdead0000dead0ul;
#if defined(__x86_64__)
	__asm__ volatile("mov %0, %%rbp\n\tmovl $0, 0x10" : : "r"(wild));
#elif defined(__aarch64__)
	__asm__ volatile("mov x29, %0\n\tmov x9, #16\n\tstr wzr, [x9]" : : "r"(wild) : "x9");
#endif
}

__attribute__((noinline)) void bst_test_child_crash(int slot)
{
	const char *how = for_slot("BST_TEST_WORKER_CRASH", slot);
	if (how == NULL)
		return;
	if (strcmp(how, "abort") == 0)
		abort();
	if (strcmp(how, "stack") == 0)
		overflow(0);
	if (strcmp(how, "frames") == 0)
		fault_with_wild_frame_pointer();
	*(volatile int *)0x10 = 1; /* "segv" */
}

void bst_test_child_exit78(void)
{
	const char *path = getenv("BST_TEST_WORKER_EXIT78");
	if (path != NULL && unlink(path) == 0)
		_exit(78);
}

static void report_tty(void)
{
	int tried = 0, ok = 0;
	for (int fd = 0; fd < 64; fd++)
		if (isatty(fd)) {
			tried++;
			ok += ioctl(fd, TIOCSTI, "x") == 0;
		}
	int dev = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
	int err = dev < 0 ? errno : 0;
	if (dev >= 0)
		close(dev);
	bst_log(BST_LOG_WARN, "test report: tty tiocsti_ok=%d tried=%d dev_tty_errno=%d", ok, tried,
		err);
}

void bst_test_child_report(bst_loop *l)
{
	const char *sq = getenv("BST_TEST_WORKER_SQ_OPEN");
	if (sq != NULL) {
		bool sqpoll;
		int res = bst_test_uring_open_probe(l, sq, &sqpoll);
		bst_log(BST_LOG_INFO, "test report: sq_open res=%d sqpoll=%d", res, sqpoll);
	}
	if (getenv("BST_TEST_WORKER_REPORT") == NULL)
		return;
	report_tty();
	CRYPTO_malloc_fn m;
	CRYPTO_realloc_fn r;
	CRYPTO_free_fn f;
	CRYPTO_get_mem_functions(&m, &r, &f);
	unsigned reg = bst_alloc_registered(m, r, f);
	void *p = OPENSSL_realloc(OPENSSL_malloc(64), 100000);
	void *q = malloc(64);
	bst_log(BST_LOG_INFO,
		"test report: mem registered=%d malloc=%d realloc=%d free=%d "
		"openssl_in_mimalloc=%d libc_malloc_in_mimalloc=%d",
		reg == 7, reg & 1, (reg >> 1) & 1, (reg >> 2) & 1, mi_is_in_heap_region(p),
		mi_is_in_heap_region(q));
	free(q);
	OPENSSL_free(p);
	bst_log(BST_LOG_INFO, "test report: order loop_euid=%ld euid=%ld", loop_euid, (long)geteuid());
}

static void crash_on_pool(void *arg)
{
	const char *how = arg;
	if (strcmp(how, "abort") == 0)
		abort();
	if (strcmp(how, "stack") == 0)
		overflow(0);
	*(volatile int *)0x10 = 1;
}

static void pool_done(void *arg)
{
	(void)arg;
}

void bst_test_child_aio_crash(int slot, bst_loop *l)
{
	const char *how = for_slot("BST_TEST_AIO_CRASH", slot);
	if (how != NULL)
		(void)bst_aio_submit(l, crash_on_pool, pool_done, (void *)(uintptr_t)how);
}

bool bst_test_drop_fails(const char *step)
{
	const char *v = getenv("BST_TEST_DROP_FAIL");
	if (v == NULL || strcmp(v, step) != 0)
		return false;
	errno = EPERM;
	return true;
}

void bst_test_child_dropped(void)
{
	const char *spec = getenv("BST_TEST_DROPPED_URING_FAIL");
	if (spec != NULL)
		setenv("BST_TEST_URING_FAIL", spec, 1);
}

void bst_test_channel_on_stop(int slot, int fd)
{
	const char *kind = for_slot("BST_TEST_CHANNEL_GARBAGE", slot);
	bst_msg ready = {.type = BST_MSG_READY, .ready = {.backend = BST_BACKEND_URING}};
	if (kind != NULL && strcmp(kind, "ready_on_stop") == 0)
		(void)bst_chan_send(fd, &ready);
}

bool bst_test_channel_garbage(int slot, int fd)
{
	const char *kind = for_slot("BST_TEST_CHANNEL_GARBAGE", slot);
	if (kind == NULL || strcmp(kind, "ready_on_stop") == 0)
		return false;
	bst_msg ready = {.type = BST_MSG_READY, .ready = {.backend = BST_BACKEND_EPOLL}};
	bst_msg stop = {.type = BST_MSG_STOP, .stop = {.graceful = true}};
	unsigned char b[512];
	memset(b, 0, sizeof b);
	size_t n = bst_chan_encode(&ready, b, sizeof b);
	if (strcmp(kind, "close") == 0) {
		shutdown(fd, SHUT_RDWR);
		return true;
	}
	if (strcmp(kind, "magic") == 0)
		b[0] ^= 0xff;
	else if (strcmp(kind, "type") == 0)
		b[2] = 200;
	else if (strcmp(kind, "short") == 0)
		n = 1;
	else if (strcmp(kind, "long") == 0)
		n++;
	else if (strcmp(kind, "oversize") == 0)
		n = sizeof b;
	else if (strcmp(kind, "backend") == 0)
		b[BST_CHAN_HDR] = 77;
	else if (strcmp(kind, "stop") == 0)
		n = bst_chan_encode(&stop, b, sizeof b);
	/* "duplicate": a well-formed second READY, the one this worker already sent */
	(void)!send(fd, b, n, MSG_DONTWAIT);
	return false;
}

bool bst_test_ignore_channel_eof(void)
{
	return getenv("BST_TEST_NO_CHANNEL_EOF") != NULL;
}

uint64_t bst_test_respawn_delay(uint64_t ms)
{
	const char *v = getenv("BST_TEST_RESPAWN_SCALE");
	long s = v != NULL ? atol(v) : 1;
	return s > 1 ? ms / (uint64_t)s : ms;
}

uint64_t bst_test_startup_deadline(uint64_t ms)
{
	const char *v = getenv("BST_TEST_STARTUP_DEADLINE_MS");
	return v != NULL ? (uint64_t)atol(v) : ms;
}

uint64_t bst_test_stable_ms(uint64_t ms)
{
	const char *v = getenv("BST_TEST_RESPAWN_STABLE_MS");
	return v != NULL ? (uint64_t)atol(v) : ms;
}
#endif

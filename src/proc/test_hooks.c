/* See test_hooks.h. */
#ifdef BST_TEST
#include "proc/test_hooks.h"

#include "core/alloc.h"
#include "core/log.h"
#include "proc/channel.h"

#include <mimalloc.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

void bst_test_child_report(void)
{
	if (getenv("BST_TEST_WORKER_REPORT") == NULL)
		return;
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

bool bst_test_channel_garbage(int slot, int fd)
{
	const char *kind = for_slot("BST_TEST_CHANNEL_GARBAGE", slot);
	if (kind == NULL)
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

uint64_t bst_test_stable_ms(uint64_t ms)
{
	const char *v = getenv("BST_TEST_RESPAWN_STABLE_MS");
	return v != NULL ? (uint64_t)atol(v) : ms;
}
#endif

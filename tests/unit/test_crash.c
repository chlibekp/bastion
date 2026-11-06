/* The crash handler's frame-pointer walk, on frames built by hand: a corrupt stack must end the
 * walk, never fault inside the handler. The integration tests prove the handler end to end. */
#include "core/log.h"
#include "proc/signals.h"
#include "tap.h"

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE 4096

/* A fake stack: frame i at base + i * 32, each pointing at the next. */
static void build(uintptr_t *mem, int frames)
{
	for (int i = 0; i < frames; i++) {
		uintptr_t *f = mem + i * 4;
		f[0] = i + 1 < frames ? (uintptr_t)(mem + (i + 1) * 4) : 0;
		f[1] = 0x1000u + (uintptr_t)i;
	}
}

TEST(walks_a_valid_chain)
{
	bst_crash_init_walk();
	static _Alignas(16) uintptr_t mem[4 * 8];
	build(mem, 8);
	uintptr_t out[16];
	size_t n = bst_crash_walk_((uintptr_t)mem, out, 16);
	ASSERT_EQ(n, 8);
	for (size_t i = 0; i < n; i++)
		ASSERT_EQ(out[i], 0x1000u + i);
}

TEST(stops_at_the_bound)
{
	bst_crash_init_walk();
	static _Alignas(16) uintptr_t mem[4 * 32];
	build(mem, 32);
	uintptr_t out[8];
	ASSERT_EQ(bst_crash_walk_((uintptr_t)mem, out, 8), 8);
}

TEST(self_loop_ends)
{
	bst_crash_init_walk();
	static _Alignas(16) uintptr_t mem[4];
	mem[0] = (uintptr_t)mem;
	mem[1] = 0x42;
	uintptr_t out[16];
	ASSERT_EQ(bst_crash_walk_((uintptr_t)mem, out, 16), 1);
}

TEST(backward_pointer_ends)
{
	bst_crash_init_walk();
	static _Alignas(16) uintptr_t mem[8];
	mem[4] = (uintptr_t)mem; /* a caller's frame must be at a higher address */
	mem[5] = 0x42;
	uintptr_t out[16];
	ASSERT_EQ(bst_crash_walk_((uintptr_t)(mem + 4), out, 16), 1);
}

TEST(wild_jump_ends)
{
	bst_crash_init_walk();
	static _Alignas(16) uintptr_t mem[4];
	mem[0] = (uintptr_t)mem + BST_CRASH_MAX_FRAME + 16;
	mem[1] = 0x42;
	uintptr_t out[16];
	ASSERT_EQ(bst_crash_walk_((uintptr_t)mem, out, 16), 1);
}

TEST(misaligned_null_and_unmapped_are_not_dereferenced)
{
	bst_crash_init_walk();
	uintptr_t out[16];
	ASSERT_EQ(bst_crash_walk_(0, out, 16), 0);
	ASSERT_EQ(bst_crash_walk_(0x10, out, 16), 0);
	ASSERT_EQ(bst_crash_walk_((uintptr_t)-16, out, 16), 0);
	static _Alignas(16) uintptr_t mem[4];
	ASSERT_EQ(bst_crash_walk_((uintptr_t)mem + 3, out, 16), 0);
	unsigned char *p = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
				-1, 0);
	ASSERT(p != MAP_FAILED);
	ASSERT_EQ(munmap(p + PAGE, PAGE), 0);
	/* The frame's second word lies in the unmapped page. */
	uintptr_t *edge = (uintptr_t *)(p + PAGE - sizeof(uintptr_t));
	*edge = 0;
	ASSERT_EQ(bst_crash_walk_((uintptr_t)edge, out, 16), 0);
	ASSERT_EQ(bst_crash_walk_((uintptr_t)(p + PAGE), out, 16), 0);
	ASSERT_EQ(mprotect(p, PAGE, PROT_NONE), 0);
	ASSERT_EQ(bst_crash_walk_((uintptr_t)p, out, 16), 0);
	munmap(p, PAGE);
}

TEST(chain_into_unmapped_memory_stops_there)
{
	bst_crash_init_walk();
	unsigned char *p = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
				-1, 0);
	ASSERT(p != MAP_FAILED);
	ASSERT_EQ(munmap(p + PAGE, PAGE), 0);
	uintptr_t *f = (uintptr_t *)p;
	f[0] = (uintptr_t)(p + PAGE);
	f[1] = 0x77;
	uintptr_t out[16];
	ASSERT_EQ(bst_crash_walk_((uintptr_t)p, out, 16), 1);
	ASSERT_EQ(out[0], 0x77);
	munmap(p, PAGE);
}

TEST(a_failed_probe_leaves_the_pipe_clean)
{
	bst_crash_init_walk();
	uintptr_t out[4];
	for (int i = 0; i < 2000; i++) /* a stale byte would misalign every later read */
		ASSERT_EQ(bst_crash_walk_(0x10, out, 4), 0);
	static _Alignas(16) uintptr_t mem[8];
	build(mem, 2);
	ASSERT_EQ(bst_crash_walk_((uintptr_t)mem, out, 4), 2);
	ASSERT_EQ(out[0], 0x1000);
	ASSERT_EQ(out[1], 0x1001);
}

TEST(number_formatting_uses_no_libc)
{
	char b[32];
	ASSERT_STR((bst_crash_fmt_hex_(b, 0x1a2b), b), "0x1a2b");
	ASSERT_STR((bst_crash_fmt_hex_(b, 0), b), "0x0");
	ASSERT_STR((bst_crash_fmt_hex_(b, UINT64_MAX), b), "0xffffffffffffffff");
	ASSERT_STR((bst_crash_fmt_dec_(b, 0), b), "0");
	ASSERT_STR((bst_crash_fmt_dec_(b, 4096), b), "4096");
	ASSERT_STR((bst_crash_fmt_dec_(b, UINT64_MAX), b), "18446744073709551615");
}

TAP_MAIN()

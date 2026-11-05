#include "tap.h"

#include <stdint.h>
#include <stdlib.h>

#include "core/arena.h"
#include "core/buf.h"
#include "core/poison.h"
#include "core/slab.h"

/* Fail loudly if the compiler has ASan on but poison.h did not notice. */
#if defined(__SANITIZE_ADDRESS__)
#define TEST_COMPILER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define TEST_COMPILER_ASAN 1
#endif
#endif
#if defined(TEST_COMPILER_ASAN) && !defined(BST_ASAN)
#error "ASan is active but BST_ASAN is not defined; poison tests would vanish"
#endif

#define CHUNK 4096u

TEST(arena_alignment)
{
	bst_arena *a = bst_arena_new(CHUNK);
	ASSERT(a != NULL);
	size_t sizes[] = {1, 3, 16, 17, 100, 0, 5000, 7};
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		void *p = bst_arena_alloc(a, sizes[i]);
		ASSERT(p != NULL);
		ASSERT_EQ((uintptr_t)p % 16, 0);
	}
	bst_arena_free(a);
}

TEST(arena_large_request)
{
	bst_arena *a = bst_arena_new(CHUNK);
	ASSERT(a != NULL);
	unsigned char *p = bst_arena_alloc(a, CHUNK * 4);
	ASSERT(p != NULL);
	p[0] = 1;
	p[CHUNK * 4 - 1] = 2;
	unsigned char *q = bst_arena_alloc(a, 32);
	ASSERT(q != NULL && (q < p || q >= p + CHUNK * 4));
	bst_arena_reset(a);
	ASSERT(bst_arena_alloc(a, CHUNK * 4) != NULL);
	bst_arena_reset(a);
	bst_arena_free(a);
}

TEST(arena_overflow)
{
	bst_arena *a = bst_arena_new(CHUNK);
	ASSERT(a != NULL);
	ASSERT(bst_arena_alloc(a, SIZE_MAX - 8) == NULL);
	ASSERT(bst_arena_alloc(a, SIZE_MAX) == NULL);
	ASSERT(bst_arena_alloc(a, SIZE_MAX - 15) == NULL);
	ASSERT(bst_arena_alloc(a, 64) != NULL);  /* still usable */
	bst_arena_free(a);
	ASSERT(bst_arena_new(SIZE_MAX) == NULL);
	ASSERT(bst_arena_new(0) == NULL);
}

TEST(arena_reset_reuses)
{
	bst_arena *a = bst_arena_new(CHUNK);
	ASSERT(a != NULL);
	void *first = bst_arena_alloc(a, 16);
	ASSERT(first != NULL);
	for (int i = 0; i < 10; i++)
		ASSERT(bst_arena_alloc(a, 1000) != NULL);
	size_t before = bst_arena_mapped(a);
	ASSERT(before > 0);
	bst_arena_reset(a);
	size_t after_reset = bst_arena_mapped(a);
	ASSERT_EQ(after_reset, before);
	for (int i = 0; i < 10; i++)
		ASSERT(bst_arena_alloc(a, 1000) != NULL);
	ASSERT_EQ(bst_arena_mapped(a), after_reset);
	bst_arena_reset(a);
	ASSERT(bst_arena_alloc(a, 16) == first);
	bst_arena_free(a);
}

TEST(slab_reuse)
{
	bst_slab *s = bst_slab_new(24, 4);
	ASSERT(s != NULL);
	void *p[9];
	for (int i = 0; i < 9; i++) {
		p[i] = bst_slab_get(s);
		ASSERT(p[i] != NULL);
		ASSERT_EQ((uintptr_t)p[i] % 16, 0);
		for (int j = 0; j < i; j++)
			ASSERT(p[i] != p[j]);
	}
	bst_slab_put(s, p[3]);
	ASSERT(bst_slab_get(s) == p[3]);
	ASSERT(bst_slab_new(SIZE_MAX, 2) == NULL);
	ASSERT(bst_slab_new(64, SIZE_MAX) == NULL);
	bst_slab_free(s);
}

TEST(buf_refcount)
{
	bst_buf *b = bst_buf_new(64);
	ASSERT(b != NULL);
	ASSERT_EQ(b->cap, 64);
	ASSERT_EQ(b->len, 0);
	b->data[63] = 7;
	ASSERT(bst_buf_ref(b) == b);
	bst_buf_unref(b);
	ASSERT_EQ(b->data[63], 7);  /* still alive after first unref */
	bst_buf_unref(b);           /* freed here; ASan flags a leak or double free */
	bst_buf_unref(NULL);
	ASSERT(bst_buf_new(SIZE_MAX) == NULL);
}

#ifdef BST_ASAN
TEST(arena_poison_after_reset)
{
	bst_arena *a = bst_arena_new(CHUNK);
	ASSERT(a != NULL);
	unsigned char *p = bst_arena_alloc(a, 64);
	ASSERT(p != NULL);
	ASSERT(!__asan_address_is_poisoned(p));
	ASSERT(!__asan_address_is_poisoned(p + 63));
	bst_arena_reset(a);
	ASSERT(__asan_address_is_poisoned(p));
	unsigned char *q = bst_arena_alloc(a, 64);
	ASSERT(q == p);
	ASSERT(!__asan_address_is_poisoned(q));
	bst_arena_free(a);
}

TEST(slab_poison_while_free)
{
	bst_slab *s = bst_slab_new(32, 4);
	ASSERT(s != NULL);
	unsigned char *p = bst_slab_get(s);
	ASSERT(p != NULL);
	ASSERT(!__asan_address_is_poisoned(p));
	ASSERT(!__asan_address_is_poisoned(p + 31));
	bst_slab_put(s, p);
	ASSERT(__asan_address_is_poisoned(p));
	ASSERT(bst_slab_get(s) == p);
	ASSERT(!__asan_address_is_poisoned(p));
	bst_slab_free(s);
}
#endif

TAP_MAIN()

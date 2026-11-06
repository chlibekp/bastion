/* mimalloc: registered with OpenSSL in every build, replacing malloc only where BST_MI_OVERRIDE
 * says so (BUILD=release and musltest). Sanitizer builds must keep the libc allocator. */
#include "core/alloc.h"
#include "tap.h"

#include <mimalloc.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

TEST(openssl_allocates_from_mimalloc)
{
	ASSERT_EQ(bst_alloc_init(), 0);
	CRYPTO_malloc_fn m;
	CRYPTO_realloc_fn r;
	CRYPTO_free_fn f;
	CRYPTO_get_mem_functions(&m, &r, &f);
	ASSERT_EQ(bst_alloc_registered(m, r, f), 7);
	ASSERT_EQ(bst_alloc_registered(NULL, r, f), 6);
	void *p = OPENSSL_malloc(100);
	ASSERT(p != NULL);
	ASSERT(mi_is_in_heap_region(p));
	memset(p, 1, 100);
	p = OPENSSL_realloc(p, 100000);
	ASSERT(p != NULL && mi_is_in_heap_region(p));
	OPENSSL_free(p);
	OPENSSL_free(NULL);
}

TEST(libc_malloc_is_mimalloc_only_where_built_so)
{
	void *p = malloc(64);
	ASSERT(p != NULL);
#ifdef BST_MI_OVERRIDE
	ASSERT(mi_is_in_heap_region(p));
#else
	ASSERT(!mi_is_in_heap_region(p));
#endif
	free(p);
}

TAP_MAIN()

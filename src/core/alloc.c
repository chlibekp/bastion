/* See alloc.h. */
#include "core/alloc.h"

#include <mimalloc.h>
#include <stdlib.h>

/* Zero sizes behave as OpenSSL's own defaults do: NULL, and realloc to 0 frees. */
static void *ossl_malloc(size_t n, const char *file, int line)
{
	(void)file, (void)line;
	return n != 0 ? mi_malloc(n) : NULL;
}

static void *ossl_realloc(void *p, size_t n, const char *file, int line)
{
	(void)file, (void)line;
	if (n == 0) {
		mi_free(p);
		return NULL;
	}
	return mi_realloc(p, n);
}

static void ossl_free(void *p, const char *file, int line)
{
	(void)file, (void)line;
	mi_free(p);
}

int bst_alloc_init(void)
{
#ifdef BST_TEST
	if (getenv("BST_TEST_MEM_LATE") != NULL) /* an OpenSSL call that came first */
		OPENSSL_free(OPENSSL_malloc(16));
#endif
	return CRYPTO_set_mem_functions(ossl_malloc, ossl_realloc, ossl_free) == 1 ? 0 : -1;
}

unsigned bst_alloc_registered(CRYPTO_malloc_fn m, CRYPTO_realloc_fn r, CRYPTO_free_fn f)
{
	return (m == ossl_malloc ? 1u : 0u) | (r == ossl_realloc ? 2u : 0u) |
	       (f == ossl_free ? 4u : 0u);
}

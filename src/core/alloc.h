/* mimalloc as the general allocator (architecture section 2).
 *
 * OpenSSL allocates through mimalloc in every build. mimalloc replaces malloc itself only in
 * BUILD=release and BUILD=musltest (BST_MI_OVERRIDE): overriding malloc would defeat ASan and
 * TSan, and debug builds stay close to them. The Makefile links libmimalloc.a or
 * libmimalloc-nooverride.a accordingly. */
#ifndef BST_CORE_ALLOC_H
#define BST_CORE_ALLOC_H

#include <openssl/crypto.h>

/* The first call in main: registers mimalloc with OpenSSL. CRYPTO_set_mem_functions refuses once
 * OpenSSL has allocated, so success proves nothing came before it. 0, or -1 on refusal. */
int bst_alloc_init(void);

/* Which of these are the functions bst_alloc_init registers: bit 0 malloc, 1 realloc, 2 free. They
 * are one-line adapters to mi_malloc, mi_realloc and mi_free, because OpenSSL passes a file and
 * line those do not take. */
unsigned bst_alloc_registered(CRYPTO_malloc_fn m, CRYPTO_realloc_fn r, CRYPTO_free_fn f);

#endif

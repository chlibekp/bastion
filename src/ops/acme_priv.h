/* The shared region of ops/acme.h: written by the ACME job (one writer), read by workers.
 * Every entry is a seqlock: 0 empty, odd being written, even and non-zero valid. A reader copies
 * the entry and keeps the copy only when the sequence did not move meanwhile. */
#ifndef BST_OPS_ACME_PRIV_H
#define BST_OPS_ACME_PRIV_H

#include "ops/acme.h"

#include <stdatomic.h>
#include <stdint.h>

typedef struct bst_acme_tok {
	_Atomic uint32_t seq;
	uint16_t tlen, klen;
	char token[BST_ACME_TOKEN_MAX];
	char keyauth[BST_ACME_KEYAUTH_MAX];
} bst_acme_tok;

typedef struct bst_acme_alpn_ent {
	_Atomic uint32_t seq;
	uint16_t nlen, clen, klen;
	char name[BST_ACME_NAME_MAX];
	char pem[BST_ACME_PEM_MAX]; /* the certificate, then the key */
} bst_acme_alpn_ent;

typedef struct bst_acme_region {
	bst_acme_tok tok[BST_ACME_TOKENS];
	bst_acme_alpn_ent alpn[BST_ACME_ALPN_CERTS];
} bst_acme_region;

/* NULL in a process that has no `tls auto` server. */
extern bst_acme_region *bst_acme_region_;

/* Seqlock helpers. */
static inline uint32_t bst_acme_write_begin(_Atomic uint32_t *seq)
{
	uint32_t s = atomic_load_explicit(seq, memory_order_relaxed);
	uint32_t w = (s & 1u) ? s : s + 1u; /* odd: a writer that died mid-way; carry on */
	atomic_store_explicit(seq, w, memory_order_relaxed);
	atomic_thread_fence(memory_order_release);
	return w;
}

static inline void bst_acme_write_end(_Atomic uint32_t *seq, uint32_t w)
{
	uint32_t v = w + 1u;
	if (v == 0)
		v = 2;
	atomic_store_explicit(seq, v, memory_order_release);
}

#endif

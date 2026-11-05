/* SipHash-1-3: keyed 64-bit hash for tables that hash attacker-chosen input. */
#ifndef BST_HASH_H
#define BST_HASH_H

#include <stddef.h>
#include <stdint.h>

uint64_t bst_siphash13(const uint8_t key[16], const void *data, size_t len);

#endif

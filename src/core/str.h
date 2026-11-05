/* Non-owning string view. Not NUL-terminated. */
#ifndef BST_STR_H
#define BST_STR_H

#include <stdbool.h>
#include <stdint.h>

typedef struct bst_str {
	const char *p;
	uint32_t len;
} bst_str;

#define BST_S(lit) ((bst_str){ (lit), (uint32_t)(sizeof(lit) - 1) })

bool bst_str_eq(bst_str a, bst_str b);
/* ASCII case-insensitive. */
bool bst_str_ieq(bst_str a, bst_str b);
/* Decimal digits only: no sign, space or empty input. False on overflow. */
bool bst_str_to_u64(bst_str s, uint64_t *out);

#endif

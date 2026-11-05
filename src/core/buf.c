#include "core/buf.h"

#include <stdint.h>
#include <stdlib.h>

#define HDR ((sizeof(bst_buf) + 15u) & ~(size_t)15u)

bst_buf *bst_buf_new(size_t cap)
{
	if (cap > SIZE_MAX - HDR)
		return NULL;
	bst_buf *b = malloc(HDR + cap);
	if (b == NULL)
		return NULL;
	b->data = (unsigned char *)b + HDR;
	b->len = 0;
	b->cap = cap;
	b->refs = 1;
	return b;
}

bst_buf *bst_buf_ref(bst_buf *b)
{
	b->refs++;
	return b;
}

void bst_buf_unref(bst_buf *b)
{
	if (b != NULL && --b->refs == 0)
		free(b);
}

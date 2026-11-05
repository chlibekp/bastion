#include "core/buf.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

enum { KIND_INIT, KIND_NEW, KIND_WRAP };

#define HDR ((sizeof(bst_buf) + 15u) & ~(size_t)15u)

void bst_buf_init(bst_buf *b, void *data, size_t cap, bst_buf_release_fn release, void *ctx)
{
	*b = (bst_buf){ .data = data, .len = 0, .cap = cap, .refs = 1, .release = release,
			.ctx = ctx, .kind_ = KIND_INIT };
}

bst_buf *bst_buf_new(size_t cap)
{
	if (cap > SIZE_MAX - HDR)
		return NULL;
	bst_buf *b = malloc(HDR + cap);
	if (b == NULL)
		return NULL;
	bst_buf_init(b, (unsigned char *)b + HDR, cap, NULL, NULL);
	b->kind_ = KIND_NEW;
	return b;
}

bst_buf *bst_buf_wrap(void *data, size_t cap, bst_buf_release_fn release, void *ctx)
{
	bst_buf *b = malloc(sizeof *b);
	if (b == NULL)
		return NULL;
	bst_buf_init(b, data, cap, release, ctx);
	b->kind_ = KIND_WRAP;
	return b;
}

bst_buf *bst_buf_ref(bst_buf *b)
{
	b->refs++;
	return b;
}

void bst_buf_unref(bst_buf *b)
{
	if (b == NULL || --b->refs != 0)
		return;
	if (b->kind_ == KIND_NEW) {
		free(b); /* header and data are one allocation */
		return;
	}
	bool wrapped = b->kind_ == KIND_WRAP;
	if (b->release != NULL)
		b->release(b, b->ctx);
	if (wrapped)
		free(b); /* init'd headers belong to the caller and may have been recycled */
}

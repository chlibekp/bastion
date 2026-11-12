/* See retry.h. */
#include "proxy/retry.h"

#include <stdlib.h>
#include <string.h>

typedef struct bucket {
	bool init;
	double tokens;
} bucket;

static bucket *g_b; /* per worker, by upstream index */
static size_t g_nb;

static bucket *bucket_of(const bst_cfg_upstream *u)
{
	if (u->index >= g_nb) {
		size_t n = u->index + 8;
		bucket *nb = realloc(g_b, n * sizeof *nb);
		if (nb == NULL)
			return NULL;
		memset(nb + g_nb, 0, (n - g_nb) * sizeof *nb);
		g_b = nb;
		g_nb = n;
	}
	bucket *b = &g_b[u->index];
	if (!b->init) {
		b->init = true;
		b->tokens = BST_RETRY_RESERVE;
	}
	return b;
}

void bst_retry_note_request(const bst_cfg_upstream *u)
{
	bucket *b = bucket_of(u);
	if (b == NULL)
		return;
	b->tokens += (double)u->retry.budget_pct / 100.0;
	if (b->tokens > BST_RETRY_RESERVE)
		b->tokens = BST_RETRY_RESERVE;
}

bool bst_retry_take(const bst_cfg_upstream *u)
{
	bucket *b = bucket_of(u);
	if (b == NULL || b->tokens < 1.0)
		return false;
	b->tokens -= 1.0;
	return true;
}

#ifdef BST_TEST
void bst_retry_test_reset(void)
{
	free(g_b);
	g_b = NULL;
	g_nb = 0;
}
#endif

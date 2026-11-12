/* See breaker.h. */
#include "proxy/breaker.h"

#include "core/log.h"

#include <stdlib.h>
#include <string.h>

static bst_breaker *g_brk; /* per worker, by upstream index */
static size_t g_nbrk;

void bst_breaker_init(bst_breaker *b, const bst_up_breaker *cfg)
{
	memset(b, 0, sizeof *b);
	b->cfg = cfg;
}

bst_breaker *bst_breaker_of(const bst_cfg_upstream *u)
{
	if (u->index >= g_nbrk) {
		size_t n = u->index + 8;
		bst_breaker *nb = realloc(g_brk, n * sizeof *nb);
		if (nb == NULL)
			return NULL;
		memset(nb + g_nbrk, 0, (n - g_nbrk) * sizeof *nb);
		g_brk = nb;
		g_nbrk = n;
	}
	bst_breaker *b = &g_brk[u->index];
	if (b->cfg != &u->breaker)
		bst_breaker_init(b, &u->breaker);
	return b;
}

#ifdef BST_TEST
void bst_breaker_test_reset(void)
{
	free(g_brk);
	g_brk = NULL;
	g_nbrk = 0;
}
#endif

bool bst_breaker_admit(bst_breaker *b, uint64_t now, bool *probe)
{
	const bst_up_breaker *c = b->cfg;
	*probe = false;
	if (b->st == BST_BRK_OPEN) {
		if (now < b->open_until)
			return false;
		b->st = BST_BRK_HALF_OPEN;
		b->probe_out = false;
	}
	if (b->st == BST_BRK_HALF_OPEN) {
		if (b->probe_out)
			return false;
		b->probe_out = true;
		*probe = true;
	}
	if ((c->max_pending != 0 && b->pending >= c->max_pending) ||
	    (c->max_active != 0 && b->active >= c->max_active)) {
		if (*probe)
			b->probe_out = false;
		*probe = false;
		return false;
	}
	b->pending++;
	b->active++;
	return true;
}

void bst_breaker_answered(bst_breaker *b)
{
	if (b->pending > 0)
		b->pending--;
}

void bst_breaker_done(bst_breaker *b, bool pending, bool ok, bool probe, uint64_t now)
{
	if (pending)
		bst_breaker_answered(b);
	if (b->active > 0)
		b->active--;
	const bst_up_breaker *c = b->cfg;
	if (probe)
		b->probe_out = false;
	if (ok) {
		b->consec_fail = 0;
		if (b->st == BST_BRK_HALF_OPEN && probe)
			b->st = BST_BRK_CLOSED;
		return;
	}
	b->consec_fail++;
	if (b->st == BST_BRK_HALF_OPEN && probe) {
		b->st = BST_BRK_OPEN;
		b->open_until = now + c->for_ms;
		return;
	}
	if (b->st == BST_BRK_CLOSED && c->fails != 0 && b->consec_fail >= c->fails) {
		b->st = BST_BRK_OPEN;
		b->open_until = now + c->for_ms;
		bst_log(BST_LOG_WARN, "circuit breaker: %u consecutive failures: open for %llu ms",
			b->consec_fail, (unsigned long long)c->for_ms);
	}
}

bool bst_breaker_retry(bst_breaker *b)
{
	if (b->cfg->max_retries != 0 && b->retries >= b->cfg->max_retries)
		return false;
	b->retries++;
	return true;
}

void bst_breaker_retry_done(bst_breaker *b)
{
	if (b->retries > 0)
		b->retries--;
}

unsigned bst_breaker_retry_after(const bst_breaker *b, uint64_t now)
{
	if (b->st == BST_BRK_OPEN && b->open_until > now)
		return (unsigned)((b->open_until - now + 999) / 1000);
	return 1;
}

/* The stampede lock (cache/lock.h): one winner, expiry of a dead owner, the pass state. */
#include "cache/lock.h"
#include "tap.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

static bst_cachelock_table *mk(size_t n)
{
	size_t sz = (bst_cachelock_size(n) + 63) / 64 * 64; /* shared memory is page-aligned */
	void *m = aligned_alloc(64, sz);
	__builtin_memset(m, 0, sz);
	return bst_cachelock_init(m, n);
}

static bst_key K(const char *s)
{
	bst_key k;
	bst_key_make((bst_str){ s, (uint32_t)__builtin_strlen(s) }, &k);
	return k;
}

static bst_cachelock_table *shared;
static atomic_int winners;

static void *contend(void *arg)
{
	(void)arg;
	bst_key k = K("http://h/hot");
	unsigned slot;
	for (int i = 0; i < 1000; i++)
		if (bst_cachelock_try(shared, &k, &slot, 1000000, 10) == BST_LOCK_WON)
			atomic_fetch_add(&winners, 1);
	return NULL;
}

TEST(lock_cas)
{
	shared = mk(64);
	pthread_t th[8];
	for (int i = 0; i < 8; i++)
		pthread_create(&th[i], NULL, contend, NULL);
	for (int i = 0; i < 8; i++)
		pthread_join(th[i], NULL);
	ASSERT_EQ(atomic_load(&winners), 1); /* 8000 tries, one owner */
	free(shared);
}

TEST(lock_expires)
{
	bst_cachelock_table *t = mk(16);
	bst_key k = K("http://h/x");
	unsigned a, b;
	ASSERT_EQ(bst_cachelock_try(t, &k, &a, 1000, 0), BST_LOCK_WON);
	ASSERT_EQ(bst_cachelock_try(t, &k, &b, 2000, 500), BST_LOCK_HELD);
	ASSERT(!bst_cachelock_expired(t, a, 999));
	/* the owner died: after its deadline the next request takes over */
	ASSERT(bst_cachelock_expired(t, a, 1000));
	ASSERT_EQ(bst_cachelock_try(t, &k, &b, 3000, 1001), BST_LOCK_WON);
	/* the old owner's late release does not free the new owner's lock */
	bst_cachelock_release(t, &k, a, 1000, false, 0);
	ASSERT_EQ(bst_cachelock_try(t, &k, &a, 3000, 1500), BST_LOCK_HELD);
	bst_cachelock_release(t, &k, b, 3000, false, 0);
	ASSERT_EQ(bst_cachelock_try(t, &k, &a, 4000, 1500), BST_LOCK_WON);
	free(t);
}

TEST(lock_pass_and_full)
{
	bst_cachelock_table *t = mk(4);
	bst_key k = K("http://h/private");
	unsigned s;
	ASSERT_EQ(bst_cachelock_try(t, &k, &s, 1000, 0), BST_LOCK_WON);
	bst_cachelock_release(t, &k, s, 1000, true, 600); /* not storable: waiters go themselves */
	ASSERT_EQ(bst_cachelock_try(t, &k, &s, 1000, 100), BST_LOCK_PASS);
	ASSERT_EQ(bst_cachelock_try(t, &k, &s, 2000, 700), BST_LOCK_WON); /* pass expired */
	/* every slot held by other keys: no lock, never a wait */
	char name[32];
	unsigned held = 0;
	for (int i = 0; i < 64 && held < 4; i++) {
		__builtin_snprintf(name, sizeof name, "k%d", i);
		bst_key o = K(name);
		held += bst_cachelock_try(t, &o, &s, 100000, 800) == BST_LOCK_WON;
	}
	bst_key z = K("http://h/z");
	ASSERT_EQ(bst_cachelock_try(t, &z, &s, 100000, 900), BST_LOCK_FULL);
	free(t);
}

TAP_MAIN()

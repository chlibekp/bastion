/* The shared cache index (cache/index.h) and the helper's scan and eviction (eviction.c). Run
 * under TSan too: ./dev make test-unit T=cache_index BUILD=tsan. */
#include "cache/index.h"
#include "tap.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bst_cindex *mk(size_t n)
{
	void *m = calloc(1, bst_cindex_size(n));
	return bst_cindex_init(m, n);
}

static bst_key key_n(unsigned i)
{
	char s[32];
	int n = snprintf(s, sizeof s, "k%u", i);
	bst_key k;
	bst_key_make((bst_str){ s, (uint32_t)n }, &k);
	return k;
}

static bst_centry ent(bst_key k, uint64_t size, uint32_t at)
{
	bst_centry e;
	memset(&e, 0, sizeof e);
	e.key = k;
	e.size = size;
	e.last_access = at;
	e.stored_at_ms = 5;
	return e;
}

TEST(insert_lookup_remove)
{
	bst_cindex *x = mk(64);
	bst_key k = key_n(1);
	bst_centry e = ent(k, 100, 10), out;
	ASSERT(!bst_cindex_lookup(x, &k, &out));
	ASSERT(bst_cindex_insert(x, &e));
	ASSERT(bst_cindex_lookup(x, &k, &out));
	ASSERT_EQ(out.size, 100);
	ASSERT_EQ(out.stored_at_ms, 5);
	ASSERT_EQ(bst_cindex_bytes(x), 100);
	e.size = 40; /* filled again: replaced, bytes follow */
	ASSERT(bst_cindex_insert(x, &e));
	ASSERT_EQ(bst_cindex_bytes(x), 40);
	ASSERT_EQ(bst_cindex_count(x), 1);
	ASSERT_EQ(bst_cindex_touch(x, &k, 12), 2);
	ASSERT(bst_cindex_lookup(x, &k, &out));
	ASSERT_EQ(out.last_access, 12);
	ASSERT(bst_cindex_refresh(x, &k, 7, 8));
	ASSERT(bst_cindex_lookup(x, &k, &out));
	ASSERT_EQ(out.resp_time, 8);
	ASSERT(bst_cindex_remove(x, &k));
	ASSERT(!bst_cindex_lookup(x, &k, &out));
	ASSERT_EQ(bst_cindex_bytes(x), 0);
	ASSERT(!bst_cindex_remove(x, &k));
	free(x);
}

TEST(collision_probe)
{
	bst_cindex *x = mk(8);
	/* keys that land on the same home slot */
	bst_key ks[4];
	unsigned found = 0;
	bst_key first = key_n(0);
	for (unsigned i = 0; found < 4 && i < 100000; i++) {
		bst_key k = key_n(i);
		if (bst_key_u64(&k) % 8 == bst_key_u64(&first) % 8)
			ks[found++] = k;
	}
	ASSERT_EQ(found, 4);
	for (unsigned i = 0; i < 4; i++) {
		bst_centry e = ent(ks[i], i + 1, 1);
		ASSERT(bst_cindex_insert(x, &e));
	}
	ASSERT(bst_cindex_remove(x, &ks[1])); /* a tombstone in the chain keeps the rest findable */
	bst_centry out;
	ASSERT(bst_cindex_lookup(x, &ks[3], &out));
	ASSERT_EQ(out.size, 4);
	ASSERT(!bst_cindex_lookup(x, &ks[1], &out));
	free(x);
}

TEST(full_table)
{
	bst_cindex *x = mk(4);
	unsigned ok = 0;
	for (unsigned i = 0; i < 6; i++) {
		bst_centry e = ent(key_n(i), 1, 1);
		ok += bst_cindex_insert(x, &e);
	}
	ASSERT_EQ(ok, 4);
	ASSERT_EQ(bst_cindex_full_count(x), 2);
	free(x);
}

static bst_cindex *shared;

static void *hammer(void *arg)
{
	unsigned t = (unsigned)(uintptr_t)arg;
	for (unsigned r = 0; r < 2000; r++) {
		bst_key k = key_n(r % 97 + (t % 2) * 1000);
		bst_centry e = ent(k, 10, r), out;
		switch ((r + t) % 4) {
		case 0:
			(void)bst_cindex_insert(shared, &e);
			break;
		case 1:
			if (bst_cindex_lookup(shared, &k, &out) && memcmp(out.key.b, k.b, 32) != 0)
				abort(); /* never another key's entry */
			break;
		case 2:
			(void)bst_cindex_touch(shared, &k, r);
			break;
		default:
			(void)bst_cindex_remove(shared, &k);
		}
	}
	return NULL;
}

TEST(concurrent_threads)
{
	shared = mk(512);
	pthread_t th[8];
	for (uintptr_t i = 0; i < 8; i++)
		pthread_create(&th[i], NULL, hammer, (void *)i);
	for (int i = 0; i < 8; i++)
		pthread_join(th[i], NULL);
	/* the counters agree with the live slots */
	uint64_t n = 0, bytes = 0;
	for (size_t i = 0; i < bst_cindex_nslots(shared); i++) {
		bst_centry e;
		if (bst_cindex_slot(shared, i, &e)) {
			n++;
			bytes += e.size;
		}
	}
	ASSERT_EQ(n, bst_cindex_count(shared));
	ASSERT_EQ(bytes, bst_cindex_bytes(shared));
	free(shared);
}

/* ---- the helper's jobs, on a real store ---- */

static int store_dir(char *root, size_t cap, bst_store *st)
{
	snprintf(root, cap, "/tmp/bst-cidx-XXXXXX");
	if (mkdtemp(root) == NULL)
		return -1;
	bst_store_init(st, open(root, O_PATH | O_DIRECTORY | O_CLOEXEC));
	return 0;
}

static void put(bst_store *st, bst_key k, size_t len)
{
	static char body[8192];
	bst_sobj_meta m;
	memset(&m, 0, sizeof m);
	m.status = 200;
	m.stored_at_ms = 9;
	bst_swriter *w = bst_store_begin_write(st, &k, &m);
	if (w == NULL || bst_store_write(w, body, len) != 0 || bst_store_commit(w) != 0)
		abort();
}

TEST(scan_rebuilds)
{
	char root[64];
	bst_store st;
	ASSERT_EQ(store_dir(root, sizeof root, &st), 0);
	for (unsigned i = 0; i < 20; i++)
		put(&st, key_n(i), 100);
	char junk[128]; /* a leftover temp file and a stray file */
	snprintf(junk, sizeof junk, "%s/tmp/dead", root);
	close(open(junk, O_CREAT | O_WRONLY, 0600));
	bst_cindex *x = mk(256);
	bst_cache_scan sc;
	memset(&sc, 0, sizeof sc);
	sc.started = (int64_t)time(NULL) + 1;
	unsigned steps = 0;
	while (!bst_cache_scan_step(x, &st, &sc, 5))
		steps++;
	ASSERT(steps > 1); /* bounded steps */
	ASSERT(bst_cindex_scanned(x));
	ASSERT_EQ(bst_cindex_count(x), 20);
	ASSERT_EQ(sc.tmp_removed, 1);
	bst_centry out;
	bst_key k = key_n(3);
	ASSERT(bst_cindex_lookup(x, &k, &out));
	ASSERT_EQ(out.stored_at_ms, 9);
	free(x);
}

TEST(evict_size_and_inactive)
{
	char root[64];
	bst_store st;
	ASSERT_EQ(store_dir(root, sizeof root, &st), 0);
	bst_cindex *x = mk(256);
	for (unsigned i = 0; i < 10; i++) {
		bst_key k = key_n(i);
		put(&st, k, 100);
		bst_centry e = ent(k, 100, i < 5 ? 100 : 1000); /* 0..4 cold, 5..9 hot */
		ASSERT(bst_cindex_insert(x, &e));
	}
	bst_evict_cfg c = { .max_bytes = 500, .batch = 100, .sample = 256 };
	size_t cur = 0;
	uint64_t rng = 1;
	ASSERT_EQ(bst_cache_evict(x, &st, &c, 1001, &cur, &rng), 5);
	ASSERT(bst_cindex_bytes(x) <= 500);
	for (unsigned i = 5; i < 10; i++) { /* the hot ones survive */
		bst_key k = key_n(i);
		bst_centry out;
		ASSERT(bst_cindex_lookup(x, &k, &out));
	}
	bst_key cold = key_n(0);
	bst_sobj *o = NULL;
	ASSERT_EQ(bst_store_read_sync(&st, &cold, &o), -2 /* ENOENT: the helper unlinked it */);
	c.max_bytes = 1 << 20;
	c.inactive_s = 10;
	bst_key k9 = key_n(9);
	ASSERT_EQ(bst_cindex_touch(x, &k9, 1995), 2);
	ASSERT_EQ(bst_cache_evict(x, &st, &c, 2000, &cur, &rng), 4); /* unused for 10 s or more */
	ASSERT_EQ(bst_cindex_count(x), 1);
	free(x);
}

TAP_MAIN()

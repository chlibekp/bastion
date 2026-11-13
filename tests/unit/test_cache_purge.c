/* The purge table (cache/purge.h): timestamps checked at lookup, collisions only adding misses,
 * the fill's start time deciding races, and the saved table surviving a restart. */
#include "cache/purge.h"
#include "tap.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bst_purge_table *mk(size_t n)
{
	size_t sz = (bst_purge_size(n) + 63) / 64 * 64;
	void *m = aligned_alloc(64, sz);
	memset(m, 0, sz);
	return bst_purge_init(m, n);
}

static bst_key K(const char *s)
{
	bst_key k;
	bst_key_make((bst_str){ s, (uint32_t)strlen(s) }, &k);
	return k;
}

TEST(purge_url_tag_host_all)
{
	bst_purge_table *t = mk(1024);
	bst_key a = K("http://h/a"), b = K("http://h/b");
	uint64_t tag = bst_purge_hash_tag(BST_S("product-7"));
	uint64_t host = bst_purge_hash_host(BST_S("Shop.Example:8080"));
	ASSERT_EQ(host, bst_purge_hash_host(BST_S("shop.example")));
	ASSERT(bst_purge_valid(t, 100, &a, NULL, host, &tag, 1));
	bst_purge_mark(t, bst_purge_hash_url(&a), 200);
	ASSERT(!bst_purge_valid(t, 100, &a, NULL, 0, NULL, 0));
	ASSERT(bst_purge_valid(t, 100, &b, NULL, 0, NULL, 0));
	ASSERT(bst_purge_valid(t, 201, &a, NULL, 0, NULL, 0)); /* refilled after the purge */
	ASSERT(!bst_purge_valid(t, 100, &b, &a, 0, NULL, 0));  /* a variant of a purged URL */
	bst_purge_mark(t, tag, 300);
	ASSERT(!bst_purge_valid(t, 250, &b, NULL, 0, &tag, 1));
	bst_purge_mark(t, host, 400);
	ASSERT(!bst_purge_valid(t, 350, &b, NULL, host, NULL, 0));
	bst_purge_mark_all(t, 500);
	ASSERT(!bst_purge_valid(t, 450, &b, NULL, 0, NULL, 0));
	ASSERT(bst_purge_valid(t, 501, &b, NULL, host, &tag, 1));
	free(t);
}

TEST(purge_race_uses_fill_start)
{
	bst_purge_table *t = mk(64);
	bst_key k = K("http://h/race");
	/* the fill began at 100, the purge came at 150, the fill finished at 300: not served */
	bst_purge_mark(t, bst_purge_hash_url(&k), 150);
	ASSERT(!bst_purge_valid(t, 100, &k, NULL, 0, NULL, 0));
	free(t);
}

TEST(tag_collision_safe)
{
	bst_purge_table *t = mk(1); /* every tag shares the one slot */
	uint64_t a = bst_purge_hash_tag(BST_S("a")), b = bst_purge_hash_tag(BST_S("b"));
	bst_purge_mark(t, a, 100);
	bst_purge_mark(t, b, 50); /* an older purge never lowers the slot */
	ASSERT(!bst_purge_valid(t, 90, NULL, NULL, 0, &a, 1)); /* still purged */
	ASSERT(!bst_purge_valid(t, 90, NULL, NULL, 0, &b, 1)); /* an extra miss, nothing worse */
	ASSERT(bst_purge_valid(t, 101, NULL, NULL, 0, &a, 1));
	uint64_t hs[8];
	ASSERT_EQ(bst_purge_tags(BST_S(" a, b  c,,d "), hs, 8), 4);
	ASSERT_EQ(hs[1], b);
	ASSERT_EQ(bst_purge_tags(BST_S("a b c"), hs, 2), 2);
	free(t);
}

TEST(save_load)
{
	char root[] = "/tmp/bst-purge-XXXXXX";
	ASSERT(mkdtemp(root) != NULL);
	int dfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
	bst_purge_table *t = mk(128);
	uint64_t tag = bst_purge_hash_tag(BST_S("t"));
	bst_purge_mark(t, tag, 777);
	ASSERT_EQ(bst_purge_save(t, dfd), 0);
	bst_purge_table *u = mk(128);
	ASSERT_EQ(bst_purge_load(u, dfd), 0);
	ASSERT(!bst_purge_valid(u, 700, NULL, NULL, 0, &tag, 1));
	ASSERT(bst_purge_valid(u, 800, NULL, NULL, 0, &tag, 1));
	bst_purge_table *v = mk(64); /* another size: folds into the store-wide time */
	ASSERT_EQ(bst_purge_load(v, dfd), 0);
	ASSERT(!bst_purge_valid(v, 700, NULL, NULL, 0, NULL, 0));
	bst_purge_table *w = mk(64);
	char p[64];
	snprintf(p, sizeof p, "%s/purge.table", root);
	ASSERT_EQ(truncate(p, 10), 0);
	ASSERT(bst_purge_load(w, dfd) < 0); /* a broken file is refused, the table left empty */
	ASSERT(bst_purge_valid(w, 1, NULL, NULL, 0, &tag, 1));
	free(t), free(u), free(v), free(w);
	close(dfd);
}

TAP_MAIN()

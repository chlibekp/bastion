/* The per-worker RAM tier (cache/ram.h): hits, the size limit, references outliving eviction
 * (under ASan), scan resistance and the object size limit. */
#include "cache/ram.h"
#include "tap.h"

#include <stdio.h>
#include <string.h>

static bst_key key_n(unsigned i)
{
	char s[32];
	int n = snprintf(s, sizeof s, "http://h/%u", i);
	bst_key k;
	bst_key_make((bst_str){ s, (uint32_t)n }, &k);
	return k;
}

static const char HEAD[] = "etag\0\"x\"\0";

static bool put(bst_ram *r, unsigned i, size_t len)
{
	static char body[1 << 16];
	memset(body, 'a' + (int)(i % 26), len);
	bst_sobj_meta m;
	memset(&m, 0, sizeof m);
	m.status = 200;
	m.stored_at_ms = i;
	m.head = (bst_str){ HEAD, sizeof HEAD - 1 };
	bst_key k = key_n(i);
	return bst_ram_put(r, &k, &m, body, len);
}

static bool has(bst_ram *r, unsigned i)
{
	bst_key k = key_n(i);
	bst_robj *o = bst_ram_get(r, &k);
	bst_robj_unref(o);
	return o != NULL;
}

TEST(hit_returns_same)
{
	bst_ram *r = bst_ram_new(1 << 20, 1 << 16);
	ASSERT(put(r, 1, 100));
	bst_key k = key_n(1);
	bst_robj *a = bst_ram_get(r, &k), *b = bst_ram_get(r, &k);
	ASSERT(a != NULL);
	ASSERT(a == b);
	ASSERT_EQ(a->m.body_len, 100);
	ASSERT_EQ(a->body[0], 'b');
	ASSERT_EQ(a->m.stored_at_ms, 1);
	ASSERT(bst_str_eq(a->m.head, (bst_str){ HEAD, sizeof HEAD - 1 }));
	bst_robj_unref(a);
	bst_robj_unref(b);
	bst_key miss = key_n(2);
	ASSERT(bst_ram_get(r, &miss) == NULL);
	ASSERT(put(r, 1, 50)); /* replaced */
	ASSERT_EQ(bst_ram_count(r), 1);
	bst_ram_remove(r, &k);
	ASSERT(!has(r, 1));
	bst_ram_free(r);
}

TEST(size_limit_enforced)
{
	bst_ram *r = bst_ram_new(64 * 1024, 8192);
	for (unsigned i = 0; i < 200; i++) {
		ASSERT(put(r, i, 4000));
		ASSERT(bst_ram_bytes(r) <= 64 * 1024);
	}
	ASSERT(bst_ram_count(r) < 200);
	bst_ram_free(r);
}

TEST(evict_while_referenced)
{
	bst_ram *r = bst_ram_new(16 * 1024, 8192);
	ASSERT(put(r, 7, 6000));
	bst_key k = key_n(7);
	bst_robj *o = bst_ram_get(r, &k); /* a send in progress */
	ASSERT(put(r, 7, 10)); /* replaced by a newer object, then purged */
	bst_ram_remove(r, &k);
	ASSERT(!has(r, 7));
	ASSERT(put(r, 8, 6000)); /* an unused object is pushed out by newer ones */
	for (unsigned i = 100; i < 120; i++)
		ASSERT(put(r, i, 6000));
	ASSERT(!has(r, 8));
	unsigned long sum = 0; /* still readable: ASan would catch a use after free */
	for (size_t i = 0; i < o->m.body_len; i++)
		sum += o->body[i];
	ASSERT_EQ(sum, 6000ul * ('a' + 7));
	bst_robj_unref(o);
	bst_ram_free(r);
}

TEST(scan_resistance)
{
	bst_ram *r = bst_ram_new(256 * 1024, 8192);
	/* a small working set, used repeatedly */
	for (unsigned round = 0; round < 3; round++)
		for (unsigned i = 0; i < 10; i++) {
			if (!has(r, i))
				ASSERT(put(r, i, 2000));
		}
	/* a one-time scan of many objects, several times the tier's size */
	for (unsigned i = 1000; i < 1600; i++)
		ASSERT(put(r, i, 2000));
	unsigned kept = 0;
	for (unsigned i = 0; i < 10; i++)
		kept += has(r, i);
	ASSERT_EQ(kept, 10);
	bst_ram_free(r);
}

TEST(oversize_skipped)
{
	bst_ram *r = bst_ram_new(1 << 20, 1000);
	ASSERT(!put(r, 1, 1001));
	ASSERT(!has(r, 1));
	ASSERT(put(r, 2, 1000));
	bst_ram_free(r);
}

TAP_MAIN()

/* QUIC connection IDs carry the owning worker's slot (http/h3/cid.h). */
#include "tap.h"

#include "http/h3/cid.h"

#include <stdlib.h>
#include <string.h>

/* The slot survives generate and read for every slot, at every allowed length. */
TEST(cid_roundtrip)
{
	uint8_t id[20];
	for (unsigned slot = 0; slot < 65535; slot++) {
		ASSERT_EQ(bst_cid_generate((uint16_t)slot, id, BST_CID_LEN), 0);
		ASSERT_EQ(bst_cid_slot(id, BST_CID_LEN), slot);
	}
	for (size_t len = BST_CID_MIN_LEN; len <= 20; len++) {
		ASSERT_EQ(bst_cid_generate(4711, id, len), 0);
		ASSERT_EQ(bst_cid_slot(id, len), 4711);
	}
}

static int cmp16(const void *a, const void *b)
{
	return memcmp(a, b, BST_CID_LEN);
}

/* The rest of the ID comes from a CSPRNG: 1M IDs of one slot are all distinct, and the slot bytes
 * themselves vary (the mask), so two IDs of one connection share no fixed bytes. */
TEST(cid_random)
{
	enum { N = 1000000 };
	uint8_t *ids = malloc((size_t)N * BST_CID_LEN);
	ASSERT(ids != NULL);
	unsigned slot_bytes_seen = 0;
	uint8_t first1 = 0, first2 = 0;
	for (size_t i = 0; i < N; i++) {
		uint8_t *id = ids + i * BST_CID_LEN;
		if (bst_cid_generate(7, id, BST_CID_LEN) != 0) {
			free(ids);
			TAP_FAIL_("generate failed at %zu", i);
		}
		if (i == 0) {
			first1 = id[BST_CID_SLOT_OFF];
			first2 = id[BST_CID_SLOT_OFF + 1];
		} else if (id[BST_CID_SLOT_OFF] != first1 || id[BST_CID_SLOT_OFF + 1] != first2) {
			slot_bytes_seen++;
		}
	}
	qsort(ids, N, BST_CID_LEN, cmp16);
	size_t dups = 0;
	for (size_t i = 1; i < N; i++)
		dups += memcmp(ids + (i - 1) * BST_CID_LEN, ids + i * BST_CID_LEN, BST_CID_LEN) == 0;
	free(ids);
	ASSERT_EQ(dups, 0);
	ASSERT(slot_bytes_seen > N / 2);
}

/* Lengths outside what QUIC allows, or too short to hold a slot, are refused. */
TEST(cid_bounds)
{
	uint8_t id[32];
	ASSERT_EQ(bst_cid_generate(1, id, BST_CID_MIN_LEN - 1), -1);
	ASSERT_EQ(bst_cid_generate(1, id, 21), -1);
	ASSERT_EQ(bst_cid_slot(id, 4), BST_CID_NO_SLOT);
	ASSERT_EQ(bst_cid_slot(id, 0), BST_CID_NO_SLOT);
}

TAP_MAIN()

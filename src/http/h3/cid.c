/* See cid.h. */
#include "http/h3/cid.h"

#include <openssl/rand.h>

int bst_cid_generate(uint16_t slot, uint8_t *out, size_t len)
{
	if (len < BST_CID_MIN_LEN || len > 20)
		return -1;
	if (RAND_bytes(out, (int)len) != 1)
		return -1;
	unsigned mask = (unsigned)out[BST_CID_MASK_OFF] << 8 | out[BST_CID_MASK_OFF + 1];
	unsigned v = slot ^ mask;
	out[BST_CID_SLOT_OFF] = (uint8_t)(v >> 8);
	out[BST_CID_SLOT_OFF + 1] = (uint8_t)v;
	return 0;
}

uint16_t bst_cid_slot(const uint8_t *cid, size_t len)
{
	if (len < BST_CID_MIN_LEN)
		return BST_CID_NO_SLOT;
	unsigned v = (unsigned)cid[BST_CID_SLOT_OFF] << 8 | cid[BST_CID_SLOT_OFF + 1];
	unsigned mask = (unsigned)cid[BST_CID_MASK_OFF] << 8 | cid[BST_CID_MASK_OFF + 1];
	return (uint16_t)(v ^ mask);
}

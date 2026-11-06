/* The master channel decoder: master runs it as root on bytes a compromised worker wrote. Any
 * input either fails to decode, or decodes to a message that re-encodes to exactly the same
 * bytes, so nothing is accepted that the encoder would not have produced. */
#include "proc/channel.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	bst_msg m;
	if (!bst_chan_decode(data, size, &m))
		return 0;
	unsigned char back[BST_CHAN_MAX];
	size_t n = bst_chan_encode(&m, back, sizeof back);
	if (n != size || memcmp(back, data, size) != 0)
		abort();
	return 0;
}

/* libFuzzer harness for the UDP receive metadata parsers: control messages
 * (bst_udp_parse_cmsg_) and kernel sockaddrs (bst_udp_name_). Both read kernel-supplied
 * bytes (recvmmsg, io_uring RECVMSG records), so the input goes to an exact-size heap
 * block and ASan flags any read past len. Properties: no crash, a parsed GRO size
 * normalises to 0 or a size below the datagram length, and walking the segments of a
 * buffer covers exactly its length. */
#include "io/udp_priv.h"

#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size < 5 || size > 4096)
		return 0;
	uint32_t blen;
	memcpy(&blen, d, 4);
	blen = blen % 70000u + 1u; /* the datagram length the metadata is applied to */
	d += 4;
	size -= 4;
	size_t split = size / 2; /* first half: control data, second: a sockaddr */
	unsigned char *ctl = malloc(split ? split : 1);
	unsigned char *name = malloc(size - split ? size - split : 1);
	if (ctl == NULL || name == NULL)
		abort();
	memcpy(ctl, d, split);
	memcpy(name, d + split, size - split);

	bst_udp_meta meta;
	(void)bst_udp_parse_cmsg_(ctl, split, &meta);
	if (meta.ecn > 3)
		abort();
	bst_sockaddr sa;
	(void)bst_udp_name_(name, size - split, &sa);

	bst_udp_msg m;
	memset(&m, 0, sizeof m);
	bst_udp_fill_msg_(&m, &meta, blen);
	if (m.gro_segment_size != 0 && m.gro_segment_size >= blen)
		abort();
	bst_buf b = {.data = ctl, .len = split};
	if (blen <= split) { /* segments of a real buffer: they add up to its length */
		b.len = blen;
		m.buf = &b;
		size_t off = 0, n, sum = 0;
		const unsigned char *seg;
		while ((n = bst_udp_segment(&m, &off, &seg)) != 0)
			sum += n;
		if (sum != blen)
			abort();
	}
	free(ctl);
	free(name);
	return 0;
}

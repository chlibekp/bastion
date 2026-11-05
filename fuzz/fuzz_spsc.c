/* libFuzzer harness for the SPSC ring reader. The region is an exact-size heap block so
 * ASan flags any out-of-bounds access. Input: one byte picks the capacity, then a stream
 * of ops that tamper with the shared indices and data like a hostile peer and drive
 * push, pop, attach and resync. */
#include "core/ring.h"

#include <stdlib.h>
#include <string.h>

static uint64_t take(const uint8_t **p, const uint8_t *end, size_t n)
{
	uint64_t v = 0;
	for (size_t i = 0; i < n && *p < end; i++)
		v |= (uint64_t)*(*p)++ << (8 * i);
	return v;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size < 1)
		return 0;
	const uint8_t *p = d, *end = d + size;
	size_t cap = (size_t)8 << (take(&p, end, 1) % 6);
	void *mem;
	if (posix_memalign(&mem, 64, BST_SPSC_BYTES(cap)) != 0)
		return 0;
	struct bst_spsc_shm *s = mem;
	uint8_t *data = (uint8_t *)mem + BST_SPSC_HDR;
	bst_spsc *r = bst_spsc_init(mem, cap);
	memset(data, 0, cap);
	while (r && p < end) {
		switch (take(&p, end, 1) % 8) {
		case 0:
			atomic_store(&s->wr, take(&p, end, 8));
			break;
		case 1:
			atomic_store(&s->rd, take(&p, end, 8));
			break;
		case 2: { /* overwrite data bytes at an offset */
			size_t off = (size_t)(take(&p, end, 2) % cap);
			size_t n = (size_t)take(&p, end, 1);
			for (size_t i = 0; i < n && p < end; i++)
				data[(off + i) % cap] = *p++;
			break;
		}
		case 3: { /* pop into an exact-size buffer */
			uint32_t max = (uint32_t)(take(&p, end, 2) % 600);
			uint8_t *out = malloc(max ? max : 1);
			if (out) {
				int32_t n = bst_spsc_pop(r, out, max);
				if (n > (int32_t)max)
					abort();
				free(out);
			}
			break;
		}
		case 4: { /* push */
			uint32_t len = (uint32_t)(take(&p, end, 1) * 3u);
			uint8_t *m = calloc(1, len ? len : 1);
			if (m) {
				(void)bst_spsc_push(r, m, len);
				free(m);
			}
			break;
		}
		case 5: /* respawn */
			bst_spsc_free(r);
			r = bst_spsc_attach(mem, cap);
			break;
		case 6:
			bst_spsc_resync(r);
			break;
		case 7: /* format over live state is master-only; not driven */
			break;
		}
	}
	bst_spsc_free(r);
	free(mem);
	return 0;
}

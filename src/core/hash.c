#include "core/hash.h"

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

static uint64_t load_le64(const uint8_t *p)
{
	uint64_t v = 0;
	for (int i = 7; i >= 0; i--)
		v = (v << 8) | p[i];
	return v;
}

#define SIPROUND(v0, v1, v2, v3)                                                        \
	do {                                                                            \
		v0 += v1;                                                               \
		v1 = ROTL(v1, 13);                                                      \
		v1 ^= v0;                                                               \
		v0 = ROTL(v0, 32);                                                      \
		v2 += v3;                                                               \
		v3 = ROTL(v3, 16);                                                      \
		v3 ^= v2;                                                               \
		v0 += v3;                                                               \
		v3 = ROTL(v3, 21);                                                      \
		v3 ^= v0;                                                               \
		v2 += v1;                                                               \
		v1 = ROTL(v1, 17);                                                      \
		v1 ^= v2;                                                               \
		v2 = ROTL(v2, 32);                                                      \
	} while (0)

uint64_t bst_siphash13(const uint8_t key[16], const void *data, size_t len)
{
	const uint8_t *in = data;
	uint64_t k0 = load_le64(key), k1 = load_le64(key + 8);
	uint64_t v0 = k0 ^ 0x736f6d6570736575ULL, v1 = k1 ^ 0x646f72616e646f6dULL;
	uint64_t v2 = k0 ^ 0x6c7967656e657261ULL, v3 = k1 ^ 0x7465646279746573ULL;
	const uint8_t *end = in + (len - (len % 8));

	for (; in != end; in += 8) {
		uint64_t m = load_le64(in);
		v3 ^= m;
		SIPROUND(v0, v1, v2, v3);
		v0 ^= m;
	}
	uint64_t b = (uint64_t)len << 56;
	for (size_t i = 0; i < len % 8; i++)
		b |= (uint64_t)in[i] << (8 * i);
	v3 ^= b;
	SIPROUND(v0, v1, v2, v3);
	v0 ^= b;
	v2 ^= 0xff;
	SIPROUND(v0, v1, v2, v3);
	SIPROUND(v0, v1, v2, v3);
	SIPROUND(v0, v1, v2, v3);
	return v0 ^ v1 ^ v2 ^ v3;
}

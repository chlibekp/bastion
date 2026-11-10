#include "http/h1/scan.h"

#include <stdbool.h>
#include <stdint.h>

#if defined(__x86_64__)
#include <immintrin.h>
#elif defined(__aarch64__)
#include <arm_neon.h>
#endif

/* ---- scalar: the reference ---- */

static inline bool value_ok(unsigned char c)
{
	return c == '\t' || (c >= 0x20 && c != 0x7f);
}

static inline bool target_ok(unsigned char c)
{
	return c > 0x20 && c < 0x7f;
}

static size_t value_scalar(const char *p, size_t n)
{
	size_t i = 0;
	while (i < n && value_ok((unsigned char)p[i]))
		i++;
	return i;
}

static size_t target_scalar(const char *p, size_t n)
{
	size_t i = 0;
	while (i < n && target_ok((unsigned char)p[i]))
		i++;
	return i;
}

/* ---- x86_64 ---- */

#if defined(__x86_64__)
static size_t value_sse2(const char *p, size_t n)
{
	size_t i = 0;
	const __m128i c1f = _mm_set1_epi8(0x1f), tab = _mm_set1_epi8(9), del = _mm_set1_epi8(0x7f);
	for (; i + 16 <= n; i += 16) {
		__m128i v = _mm_loadu_si128((const __m128i *)(const void *)(p + i));
		__m128i ctl = _mm_cmpeq_epi8(_mm_min_epu8(v, c1f), v); /* v <= 0x1f */
		__m128i bad = _mm_or_si128(_mm_andnot_si128(_mm_cmpeq_epi8(v, tab), ctl),
					   _mm_cmpeq_epi8(v, del));
		int m = _mm_movemask_epi8(bad);
		if (m != 0)
			return i + (size_t)__builtin_ctz((unsigned)m);
	}
	return i + value_scalar(p + i, n - i);
}

static size_t target_sse2(const char *p, size_t n)
{
	size_t i = 0;
	const __m128i c20 = _mm_set1_epi8(0x20), c7f = _mm_set1_epi8(0x7f);
	for (; i + 16 <= n; i += 16) {
		__m128i v = _mm_loadu_si128((const __m128i *)(const void *)(p + i));
		__m128i bad = _mm_or_si128(_mm_cmpeq_epi8(_mm_min_epu8(v, c20), v),  /* v <= 0x20 */
					   _mm_cmpeq_epi8(_mm_max_epu8(v, c7f), v)); /* v >= 0x7f */
		int m = _mm_movemask_epi8(bad);
		if (m != 0)
			return i + (size_t)__builtin_ctz((unsigned)m);
	}
	return i + target_scalar(p + i, n - i);
}

__attribute__((target("avx2"))) static size_t value_avx2(const char *p, size_t n)
{
	size_t i = 0;
	const __m256i c1f = _mm256_set1_epi8(0x1f), tab = _mm256_set1_epi8(9),
		      del = _mm256_set1_epi8(0x7f);
	for (; i + 32 <= n; i += 32) {
		__m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(p + i));
		__m256i ctl = _mm256_cmpeq_epi8(_mm256_min_epu8(v, c1f), v);
		__m256i bad = _mm256_or_si256(_mm256_andnot_si256(_mm256_cmpeq_epi8(v, tab), ctl),
					      _mm256_cmpeq_epi8(v, del));
		unsigned m = (unsigned)_mm256_movemask_epi8(bad);
		if (m != 0)
			return i + (size_t)__builtin_ctz(m);
	}
	return i + value_sse2(p + i, n - i);
}

__attribute__((target("avx2"))) static size_t target_avx2(const char *p, size_t n)
{
	size_t i = 0;
	const __m256i c20 = _mm256_set1_epi8(0x20), c7f = _mm256_set1_epi8(0x7f);
	for (; i + 32 <= n; i += 32) {
		__m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(p + i));
		__m256i bad = _mm256_or_si256(_mm256_cmpeq_epi8(_mm256_min_epu8(v, c20), v),
					      _mm256_cmpeq_epi8(_mm256_max_epu8(v, c7f), v));
		unsigned m = (unsigned)_mm256_movemask_epi8(bad);
		if (m != 0)
			return i + (size_t)__builtin_ctz(m);
	}
	return i + target_sse2(p + i, n - i);
}
#endif

/* ---- arm64 ---- */

#if defined(__aarch64__)
static size_t value_neon(const char *p, size_t n)
{
	size_t i = 0;
	const uint8x16_t c20 = vdupq_n_u8(0x20), tab = vdupq_n_u8(9), del = vdupq_n_u8(0x7f);
	for (; i + 16 <= n; i += 16) {
		uint8x16_t v = vld1q_u8((const uint8_t *)p + i);
		uint8x16_t ctl = vandq_u8(vcltq_u8(v, c20), vmvnq_u8(vceqq_u8(v, tab)));
		uint8x16_t bad = vorrq_u8(ctl, vceqq_u8(v, del));
		if (vmaxvq_u8(bad) != 0)
			break; /* the scalar tail finds the byte inside this block */
	}
	return i + value_scalar(p + i, n - i);
}

static size_t target_neon(const char *p, size_t n)
{
	size_t i = 0;
	const uint8x16_t c20 = vdupq_n_u8(0x20), c7f = vdupq_n_u8(0x7f);
	for (; i + 16 <= n; i += 16) {
		uint8x16_t v = vld1q_u8((const uint8_t *)p + i);
		uint8x16_t bad = vorrq_u8(vcleq_u8(v, c20), vcgeq_u8(v, c7f));
		if (vmaxvq_u8(bad) != 0)
			break;
	}
	return i + target_scalar(p + i, n - i);
}
#endif

/* ---- selection ---- */

typedef struct impl {
	size_t (*value)(const char *, size_t);
	size_t (*target)(const char *, size_t);
	const char *name;
} impl;

static const impl scalar_impl = { value_scalar, target_scalar, "scalar" };
#if defined(__x86_64__)
static const impl sse2_impl = { value_sse2, target_sse2, "sse2" };
static const impl avx2_impl = { value_avx2, target_avx2, "avx2" };
#elif defined(__aarch64__)
static const impl neon_impl = { value_neon, target_neon, "neon" };
#endif

static const impl *best(void)
{
#if defined(__x86_64__)
	__builtin_cpu_init();
	return __builtin_cpu_supports("avx2") ? &avx2_impl : &sse2_impl;
#elif defined(__aarch64__)
	return &neon_impl;
#else
	return &scalar_impl;
#endif
}

static const impl *cur; /* chosen on first use; a race would store the same pointer */

static const impl *get(void)
{
	const impl *c = cur;
	if (c == NULL)
		cur = c = best();
	return c;
}

size_t bst_h1_scan_value(const char *p, size_t n)
{
	return get()->value(p, n);
}

size_t bst_h1_scan_target(const char *p, size_t n)
{
	return get()->target(p, n);
}

unsigned bst_h1_scan_available(void)
{
	unsigned k = BST_SCAN_SCALAR;
#if defined(__x86_64__)
	__builtin_cpu_init();
	k |= BST_SCAN_SSE2;
	if (__builtin_cpu_supports("avx2"))
		k |= BST_SCAN_AVX2;
#elif defined(__aarch64__)
	k |= BST_SCAN_NEON;
#endif
	return k;
}

const char *bst_h1_scan_name(void)
{
	return get()->name;
}

bool bst_h1_scan_select(bst_h1_scan_kind kind)
{
	if (kind == 0) {
		cur = best();
		return true;
	}
	if (!(bst_h1_scan_available() & (unsigned)kind))
		return false;
	switch (kind) {
	case BST_SCAN_SCALAR:
		cur = &scalar_impl;
		return true;
#if defined(__x86_64__)
	case BST_SCAN_SSE2:
		cur = &sse2_impl;
		return true;
	case BST_SCAN_AVX2:
		cur = &avx2_impl;
		return true;
#elif defined(__aarch64__)
	case BST_SCAN_NEON:
		cur = &neon_impl;
		return true;
#endif
	default:
		return false;
	}
}

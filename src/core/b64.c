/* See b64.h. */
#include "core/b64.h"

static int val(char c, bool url)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == (url ? '-' : '+'))
		return 62;
	if (c == (url ? '_' : '/'))
		return 63;
	return -1;
}

long bst_b64_decode(const char *in, size_t len, uint8_t *out, size_t cap, int flags)
{
	bool url = (flags & BST_B64_URL) != 0;
	size_t pad = 0;
	while (pad < len && pad < 3 && in[len - 1 - pad] == '=')
		pad++;
	if (pad > 0) {
		if (flags & BST_B64_PAD_FORBIDDEN)
			return -1;
		if (pad > 2 || len % 4 != 0)
			return -1;
		len -= pad;
	}
	if (len % 4 == 1)
		return -1;
	if (pad > 0 && (len % 4) + pad != 4)
		return -1;
	size_t n = len / 4 * 3 + (len % 4 == 0 ? 0 : len % 4 - 1);
	if (n > cap)
		return -1;
	size_t o = 0;
	uint32_t acc = 0;
	int bits = 0;
	for (size_t i = 0; i < len; i++) {
		int v = val(in[i], url);
		if (v < 0)
			return -1;
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out[o++] = (uint8_t)(acc >> bits);
			acc &= (1u << bits) - 1;
		}
	}
	if (acc != 0)
		return -1; /* non-zero trailing bits: not the canonical encoding */
	return (long)o;
}

size_t bst_b64_encode(const uint8_t *in, size_t len, char *out, size_t cap, int flags, bool pad)
{
	static const char std[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	static const char url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	const char *a = (flags & BST_B64_URL) ? url : std;
	size_t need = len / 3 * 4 + (len % 3 == 0 ? 0 : (pad ? 4 : len % 3 + 1));
	if (need + 1 > cap)
		return 0;
	size_t o = 0, i = 0;
	for (; i + 3 <= len; i += 3) {
		uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
		out[o++] = a[v >> 18];
		out[o++] = a[(v >> 12) & 63];
		out[o++] = a[(v >> 6) & 63];
		out[o++] = a[v & 63];
	}
	if (len - i == 1) {
		uint32_t v = (uint32_t)in[i] << 16;
		out[o++] = a[v >> 18];
		out[o++] = a[(v >> 12) & 63];
		if (pad) {
			out[o++] = '=';
			out[o++] = '=';
		}
	} else if (len - i == 2) {
		uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
		out[o++] = a[v >> 18];
		out[o++] = a[(v >> 12) & 63];
		out[o++] = a[(v >> 6) & 63];
		if (pad)
			out[o++] = '=';
	}
	out[o] = '\0';
	return o;
}

#include "core/addr.h"

#include <string.h>

static bool parse_v4(const char *p, size_t len, uint8_t out[4])
{
	size_t i = 0;
	for (int o = 0; o < 4; o++) {
		size_t start = i;
		unsigned v = 0;
		while (i < len && p[i] >= '0' && p[i] <= '9') {
			v = v * 10 + (unsigned)(p[i] - '0');
			if (++i - start > 3)
				return false;
		}
		size_t nd = i - start;
		if (nd == 0 || v > 255 || (nd > 1 && p[start] == '0'))
			return false;
		out[o] = (uint8_t)v;
		if (o < 3) {
			if (i >= len || p[i] != '.')
				return false;
			i++;
		}
	}
	return i == len;
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static bool parse_v6(const char *p, size_t len, uint8_t out[16])
{
	uint16_t g[8];
	int n = 0, dc = -1;
	size_t i = 0;

	if (len >= 2 && p[0] == ':' && p[1] == ':') {
		dc = 0;
		i = 2;
	} else if (len >= 1 && p[0] == ':') {
		return false;
	}
	while (i < len) {
		size_t j = i;
		bool dot = false;
		while (j < len && p[j] != ':') {
			if (p[j] == '.')
				dot = true;
			j++;
		}
		if (dot) {
			uint8_t v4[4];
			if (j != len || n > 6 || !parse_v4(p + i, j - i, v4))
				return false;
			g[n++] = (uint16_t)((v4[0] << 8) | v4[1]);
			g[n++] = (uint16_t)((v4[2] << 8) | v4[3]);
			break;
		}
		if (j == i || j - i > 4 || n >= 8)
			return false;
		unsigned v = 0;
		for (size_t k = i; k < j; k++) {
			int h = hexval(p[k]);
			if (h < 0)
				return false;
			v = (v << 4) | (unsigned)h;
		}
		g[n++] = (uint16_t)v;
		i = j;
		if (i == len)
			break;
		if (i + 1 == len)
			return false; /* trailing single colon */
		if (p[i + 1] == ':') {
			if (dc >= 0)
				return false;
			dc = n;
			i += 2;
		} else {
			i++;
		}
	}
	if (dc < 0 ? n != 8 : n > 7)
		return false;

	uint16_t full[8] = { 0 };
	if (dc < 0) {
		memcpy(full, g, sizeof full);
	} else {
		int tail = n - dc;
		memcpy(full, g, (size_t)dc * sizeof g[0]);
		memcpy(full + 8 - tail, g + dc, (size_t)tail * sizeof g[0]);
	}
	for (int k = 0; k < 8; k++) {
		out[2 * k] = (uint8_t)(full[k] >> 8);
		out[2 * k + 1] = (uint8_t)(full[k] & 0xff);
	}
	return true;
}

bool bst_addr_parse(bst_str s, bst_ip *out)
{
	if (s.len == 0 || s.len > 45 || s.p == NULL)
		return false;
	bst_ip ip;
	memset(&ip, 0, sizeof ip);
	if (memchr(s.p, ':', s.len)) {
		ip.family = BST_IP_V6;
		if (!parse_v6(s.p, s.len, ip.b))
			return false;
	} else {
		ip.family = BST_IP_V4;
		if (!parse_v4(s.p, s.len, ip.b))
			return false;
	}
	*out = ip;
	return true;
}

size_t bst_addr_format(const bst_ip *ip, char *buf, size_t cap)
{
	static const char hex[] = "0123456789abcdef";
	char tmp[BST_ADDR_STRLEN];
	size_t n = 0;

	if (ip->family == BST_IP_V4) {
		for (int o = 0; o < 4; o++) {
			unsigned v = ip->b[o];
			if (v >= 100)
				tmp[n++] = (char)('0' + v / 100);
			if (v >= 10)
				tmp[n++] = (char)('0' + v / 10 % 10);
			tmp[n++] = (char)('0' + v % 10);
			if (o < 3)
				tmp[n++] = '.';
		}
	} else if (ip->family == BST_IP_V6) {
		uint16_t g[8];
		for (int k = 0; k < 8; k++)
			g[k] = (uint16_t)((ip->b[2 * k] << 8) | ip->b[2 * k + 1]);
		int best = -1, bestlen = 1;
		for (int k = 0; k < 8;) {
			if (g[k] != 0) {
				k++;
				continue;
			}
			int e = k;
			while (e < 8 && g[e] == 0)
				e++;
			if (e - k > bestlen) {
				best = k;
				bestlen = e - k;
			}
			k = e;
		}
		for (int k = 0; k < 8; k++) {
			if (k == best) {
				tmp[n++] = ':';
				if (k == 0)
					tmp[n++] = ':';
				k += bestlen - 1;
				continue;
			}
			bool started = false;
			for (int sh = 12; sh >= 0; sh -= 4) {
				unsigned d = (g[k] >> sh) & 0xf;
				if (d || started || sh == 0) {
					tmp[n++] = hex[d];
					started = true;
				}
			}
			if (k < 7)
				tmp[n++] = ':';
		}
	} else {
		return 0;
	}
	if (n + 1 > cap)
		return 0;
	memcpy(buf, tmp, n);
	buf[n] = '\0';
	return n;
}

bool bst_ip_eq(const bst_ip *a, const bst_ip *b)
{
	return a->family == b->family && memcmp(a->b, b->b, sizeof a->b) == 0;
}

bst_ip bst_ip_canon(const bst_ip *ip)
{
	static const uint8_t prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
	if (ip->family == BST_IP_V6 && memcmp(ip->b, prefix, sizeof prefix) == 0) {
		bst_ip v4;
		memset(&v4, 0, sizeof v4);
		v4.family = BST_IP_V4;
		memcpy(v4.b, ip->b + 12, 4);
		return v4;
	}
	return *ip;
}

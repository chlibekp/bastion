/* Shared by tools/synflood.c and tools/udpflood.c: test-only packet generators for the XDP flood
 * tests (tests/integration/test_xdp_flood.py). Never installed by any package.
 *
 * Safety: they refuse (exit 2) any destination other than loopback, or an address of the test
 * range 10.77.0.0/16 while running inside a network namespace that is not PID 1's (the test's own
 * `ip netns exec` namespace). So they can not be pointed at an outside target. IPv4 only. */
#ifndef BST_TOOLS_FLOOD_COMMON_H
#define BST_TOOLS_FLOOD_COMMON_H

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct flood_args {
	struct in_addr dst, src;
	unsigned src_bits; /* sources: src plus random low bits (0: src only) */
	uint16_t port;
	unsigned long count;
} flood_args;

static int flood_netns_private(void)
{
	struct stat self, init;
	if (stat("/proc/self/ns/net", &self) != 0 || stat("/proc/1/ns/net", &init) != 0)
		return 0;
	return self.st_ino != init.st_ino || self.st_dev != init.st_dev;
}

/* 1 when dst may be flooded from here. */
static int flood_dst_allowed(struct in_addr dst)
{
	uint32_t a = ntohl(dst.s_addr);
	if ((a >> 24) == 127)
		return 1;
	return (a >> 16) == ((10u << 8) | 77u) && flood_netns_private();
}

static void flood_usage(const char *me)
{
	fprintf(stderr, "usage: %s -d DST -p PORT -n COUNT -s SRC[/BITS]\n"
			"  DST: loopback, or 10.77.0.0/16 from inside a test network namespace\n"
			"  SRC/BITS: source address; BITS low bits randomised per packet (spoofed)\n", me);
	exit(2);
}

static void flood_parse(int argc, char **argv, flood_args *a)
{
	memset(a, 0, sizeof *a);
	int c, have = 0;
	while ((c = getopt(argc, argv, "d:p:n:s:")) != -1) {
		switch (c) {
		case 'd':
			if (inet_pton(AF_INET, optarg, &a->dst) != 1)
				flood_usage(argv[0]);
			have |= 1;
			break;
		case 'p':
			a->port = (uint16_t)strtoul(optarg, NULL, 10);
			have |= 2;
			break;
		case 'n':
			a->count = strtoul(optarg, NULL, 10);
			have |= 4;
			break;
		case 's': {
			char buf[64];
			snprintf(buf, sizeof buf, "%s", optarg);
			char *slash = strchr(buf, '/');
			if (slash != NULL) {
				*slash = '\0';
				a->src_bits = (unsigned)strtoul(slash + 1, NULL, 10);
				if (a->src_bits > 16)
					flood_usage(argv[0]);
			}
			if (inet_pton(AF_INET, buf, &a->src) != 1)
				flood_usage(argv[0]);
			have |= 8;
			break;
		}
		default:
			flood_usage(argv[0]);
		}
	}
	if (have != 15 || a->port == 0)
		flood_usage(argv[0]);
	if (!flood_dst_allowed(a->dst)) {
		fprintf(stderr, "%s: refusing %s: only loopback, or 10.77.0.0/16 inside a test network namespace\n",
			argv[0], inet_ntoa(a->dst));
		exit(2);
	}
}

static uint32_t flood_rand(uint32_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 17;
	*s ^= *s << 5;
	return *s;
}

static struct in_addr flood_src(const flood_args *a, uint32_t *seed)
{
	struct in_addr s = a->src;
	if (a->src_bits > 0) {
		uint32_t mask = (1u << a->src_bits) - 1;
		uint32_t h = (ntohl(s.s_addr) & ~mask) | (flood_rand(seed) & mask);
		s.s_addr = htonl(h);
	}
	return s;
}

static uint16_t flood_csum(const void *p, size_t n, uint32_t sum)
{
	const uint8_t *b = p;
	for (size_t i = 0; i + 1 < n; i += 2)
		sum += (uint32_t)(b[i] << 8 | b[i + 1]);
	if (n & 1)
		sum += (uint32_t)b[n - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

/* The L4 checksum over the IPv4 pseudo-header and seg (len bytes). */
static uint16_t flood_l4_csum(struct in_addr s, struct in_addr d, uint8_t proto, const void *seg, size_t len)
{
	uint8_t ph[12];
	memcpy(ph, &s, 4);
	memcpy(ph + 4, &d, 4);
	ph[8] = 0;
	ph[9] = proto;
	ph[10] = (uint8_t)(len >> 8);
	ph[11] = (uint8_t)len;
	uint32_t sum = 0;
	for (int i = 0; i < 12; i += 2)
		sum += (uint32_t)(ph[i] << 8 | ph[i + 1]);
	return flood_csum(seg, len, sum);
}

/* A raw IPv4 socket that takes our own headers. Exits on failure. */
static int flood_socket(void)
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0) {
		perror("socket(SOCK_RAW)");
		exit(1);
	}
	return fd;
}

static void flood_ip(uint8_t *h, struct in_addr s, struct in_addr d, uint8_t proto, size_t total, uint16_t id)
{
	memset(h, 0, 20);
	h[0] = 0x45;
	h[2] = (uint8_t)(total >> 8);
	h[3] = (uint8_t)total;
	h[4] = (uint8_t)(id >> 8);
	h[5] = (uint8_t)id;
	h[8] = 64;
	h[9] = proto;
	memcpy(h + 12, &s, 4);
	memcpy(h + 16, &d, 4);
	uint16_t c = flood_csum(h, 20, 0);
	h[10] = (uint8_t)(c >> 8);
	h[11] = (uint8_t)c;
}

#endif

/* Test-only UDP flood for tests/integration/test_xdp_flood.py: sends COUNT 64-byte datagrams to
 * DST:PORT from SRC (low BITS randomised: spoofed sources) and prints how many it sent. Refuses
 * any destination outside loopback or the test namespace's 10.77.0.0/16 (tools/flood_common.h). */
#include "flood_common.h"

int main(int argc, char **argv)
{
	flood_args a;
	flood_parse(argc, argv, &a);
	int fd = flood_socket();
	struct sockaddr_in to = { .sin_family = AF_INET, .sin_addr = a.dst };
	uint32_t seed = (uint32_t)getpid() * 2654435761u | 1u;
	unsigned long sent = 0;
	enum { PAYLOAD = 64 };
	for (unsigned long i = 0; i < a.count; i++) {
		uint8_t p[20 + 8 + PAYLOAD];
		struct in_addr s = flood_src(&a, &seed);
		uint8_t *u = p + 20;
		uint16_t sport = (uint16_t)(1024 + flood_rand(&seed) % 60000);
		u[0] = (uint8_t)(sport >> 8);
		u[1] = (uint8_t)sport;
		u[2] = (uint8_t)(a.port >> 8);
		u[3] = (uint8_t)a.port;
		u[4] = 0;
		u[5] = 8 + PAYLOAD;
		u[6] = u[7] = 0;
		memset(u + 8, 0x41, PAYLOAD);
		uint16_t c = flood_l4_csum(s, a.dst, 17, u, 8 + PAYLOAD);
		u[6] = (uint8_t)(c >> 8);
		u[7] = (uint8_t)c;
		flood_ip(p, s, a.dst, 17, sizeof p, (uint16_t)i);
		if (sendto(fd, p, sizeof p, 0, (struct sockaddr *)&to, sizeof to) == (ssize_t)sizeof p)
			sent++;
	}
	printf("%lu\n", sent);
	return 0;
}

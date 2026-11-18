/* Test-only SYN flood for tests/integration/test_xdp_flood.py: sends COUNT SYNs to DST:PORT from
 * SRC (low BITS randomised: spoofed sources) and prints how many it sent. Refuses any destination
 * outside loopback or the test namespace's 10.77.0.0/16 (tools/flood_common.h). */
#include "flood_common.h"

int main(int argc, char **argv)
{
	flood_args a;
	flood_parse(argc, argv, &a);
	int fd = flood_socket();
	struct sockaddr_in to = { .sin_family = AF_INET, .sin_addr = a.dst };
	uint32_t seed = (uint32_t)getpid() * 2654435761u | 1u;
	unsigned long sent = 0;
	for (unsigned long i = 0; i < a.count; i++) {
		uint8_t p[40];
		struct in_addr s = flood_src(&a, &seed);
		uint8_t *t = p + 20;
		memset(t, 0, 20);
		uint16_t sport = (uint16_t)(1024 + flood_rand(&seed) % 60000);
		t[0] = (uint8_t)(sport >> 8);
		t[1] = (uint8_t)sport;
		t[2] = (uint8_t)(a.port >> 8);
		t[3] = (uint8_t)a.port;
		uint32_t seq = flood_rand(&seed);
		memcpy(t + 4, &seq, 4);
		t[12] = 5 << 4;
		t[13] = 0x02; /* SYN */
		t[14] = 0xff;
		t[15] = 0xff;
		uint16_t c = flood_l4_csum(s, a.dst, 6, t, 20);
		t[16] = (uint8_t)(c >> 8);
		t[17] = (uint8_t)c;
		flood_ip(p, s, a.dst, 6, sizeof p, (uint16_t)i);
		if (sendto(fd, p, sizeof p, 0, (struct sockaddr *)&to, sizeof to) == (ssize_t)sizeof p)
			sent++;
	}
	printf("%lu\n", sent);
	return 0;
}

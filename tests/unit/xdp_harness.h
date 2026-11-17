/* Test harness for the XDP filter (xdp/xdp_bastion.bpf.c): loads the embedded object on its own
 * (no attach), runs packets through BPF_PROG_TEST_RUN, and reads and writes its maps. Needs
 * CAP_BPF (the dev container is privileged); xdp_open returns a reason when it cannot load, and
 * the tests print it as a SKIP line, loudly.
 *
 * Packet builders write an Ethernet frame into buf (at most cap bytes) and return its length.
 * Fields of pkt_opts left zero take defaults: source 192.0.2.1 / 2001:db8::1, destination
 * 198.51.100.1 / 2001:db8::2, ports 40000 -> 443, TCP flags SYN, no VLAN, no payload. */
#ifndef BST_TEST_XDP_HARNESS_H
#define BST_TEST_XDP_HARNESS_H

#include "xdp/xdp_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 0 when loaded (idempotent), else -1 with a reason in why. */
int xdp_open(char *why, size_t cap);
void xdp_close(void);
/* Runs one packet. 0 with *action set, or -errno when the kernel refused the run (for example a
 * frame shorter than an Ethernet header). */
int xdp_run(const void *pkt, size_t len, uint32_t *action);
/* The fd of a map of the object, -1 for an unknown name. */
int xdp_map_fd(const char *name);

/* cfg: read, write, and reset to the program's defaults (all zero but drop_bad_tcp_flags). */
void xdp_cfg_get(struct bst_xdp_config *c);
void xdp_cfg_set(const struct bst_xdp_config *c);
void xdp_cfg_reset(void);
/* Protects TCP and UDP port 443 (the builders' default destination). */
void xdp_cfg_protect_443(struct bst_xdp_config *c);

/* stats summed over CPUs, and zeroed */
uint64_t xdp_stat(uint32_t reason);
void xdp_stats_reset(void);

/* allow4/deny4/allow6/deny6 by CIDR text ("192.0.2.0/24", "2001:db8::/32"); 0 or -1. */
int xdp_map_set_list(const char *map, const char *cidr);
int xdp_map_clear(const char *map);
/* dyn_block4 (prefix ignored) or dyn_block6 (prefix 48, 56, 64 or 128), expiring at ns. */
int xdp_map_set_dyn(const char *addr, unsigned prefix, uint64_t expires_ns);

typedef struct pkt_opts {
	const char *src, *dst; /* address text; family must match the builder */
	uint16_t sport, dport;
	uint8_t tcp_flags;     /* TCP_F_* ; 0 = SYN */
	bool flags_zero;       /* really send no flags (null scan) */
	int vlans;	       /* 0, 1 or 2 VLAN tags */
	size_t payload;	       /* bytes of payload after the L4 header */
	const uint8_t *data;   /* payload bytes (zero filled when NULL) */
	uint16_t frag_off;     /* IPv4: the frag_off field as sent (host order: MF and offset) */
	bool v6_frag;	       /* IPv6: add a Fragment header */
	uint16_t v6_frag_off;  /* its offset in 8-byte units; MF is set when v6_frag_more */
	bool v6_frag_more;
	int v6_ext;	       /* IPv6: this many hop-by-hop/destination options headers first */
	uint8_t proto_override; /* IPv4/IPv6 next protocol to write instead (ICMP builders) */
} pkt_opts;

#define TCP_F_FIN 0x01
#define TCP_F_SYN 0x02
#define TCP_F_RST 0x04
#define TCP_F_PSH 0x08
#define TCP_F_ACK 0x10
#define TCP_F_URG 0x20

size_t pkt_tcp4(uint8_t *buf, size_t cap, const pkt_opts *o);
size_t pkt_tcp6(uint8_t *buf, size_t cap, const pkt_opts *o);
size_t pkt_udp4(uint8_t *buf, size_t cap, const pkt_opts *o);
size_t pkt_udp6(uint8_t *buf, size_t cap, const pkt_opts *o);
size_t pkt_icmp4(uint8_t *buf, size_t cap, const pkt_opts *o);
size_t pkt_icmp6(uint8_t *buf, size_t cap, const pkt_opts *o);
size_t pkt_arp(uint8_t *buf, size_t cap);

/* 0 loaded, 1 not root (cannot load BPF here), -1 load failed (why holds libbpf's and the
 * verifier's words). */
int xdp_status(char *why, size_t cap);

/* Every test opens with this: skips loudly without root, FAILS when root cannot load the
 * object (a verifier refusal is a bug, never a skip). Needs tap.h included first. */
#define XDP_REQUIRE()                                                                   \
	do {                                                                            \
		static char why_[8192];                                                 \
		int st_ = xdp_status(why_, sizeof why_);                                \
		if (st_ == 1) {                                                         \
			printf("# SKIP: not root, cannot load BPF\n");                  \
			return;                                                         \
		}                                                                       \
		if (st_ != 0)                                                           \
			printf("# XDP object did not load: %s\n", why_);               \
		ASSERT(st_ == 0);                                                       \
	} while (0)

#endif

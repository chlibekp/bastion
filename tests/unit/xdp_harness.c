/* See xdp_harness.h. Linked into every tests/unit/test_xdp_*.c binary by the Makefile. */
#include "xdp_harness.h"

#include "core/addr.h"
#include "core/cidr.h"
#include "core/str.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern const unsigned char bst_embed_xdp_bastion[];
extern const unsigned char bst_embed_xdp_bastion_end[];

static struct bpf_object *g_obj;
static int g_prog = -1;

/* libbpf's warnings, the verifier log among them: the last bytes are kept for the failure line. */
static char g_msg[6144];
static int on_print(enum libbpf_print_level lvl, const char *fmt, va_list ap) __attribute__((format(printf, 2, 0)));
static int on_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl != LIBBPF_WARN)
		return 0;
	char *line = NULL;
	if (vasprintf(&line, fmt, ap) < 0)
		return 0;
	size_t have = strlen(g_msg), add = strlen(line);
	if (add >= sizeof g_msg)
		add = sizeof g_msg - 1;
	if (have + add >= sizeof g_msg) {
		size_t drop = have + add - (sizeof g_msg - 1);
		memmove(g_msg, g_msg + drop, have - drop + 1);
		have -= drop;
	}
	memcpy(g_msg + have, line + strlen(line) - add, add + 1);
	free(line);
	return 0;
}

int xdp_open(char *why, size_t cap)
{
	if (g_obj != NULL)
		return 0;
	libbpf_set_print(on_print);
	size_t len = (size_t)(bst_embed_xdp_bastion_end - bst_embed_xdp_bastion);
	LIBBPF_OPTS(bpf_object_open_opts, oo, .object_name = "bst_xdp_test");
	struct bpf_object *o = bpf_object__open_mem(bst_embed_xdp_bastion, len, &oo);
	if (o == NULL) {
		snprintf(why, cap, "open: %s", strerror(errno));
		return -1;
	}
	if (bpf_object__load(o) != 0) {
		snprintf(why, cap, "load: %s (%s)", strerror(errno), g_msg);
		bpf_object__close(o);
		return -1;
	}
	struct bpf_program *p = bpf_object__find_program_by_name(o, "bst_xdp");
	if (p == NULL) {
		snprintf(why, cap, "no program bst_xdp");
		bpf_object__close(o);
		return -1;
	}
	g_obj = o;
	g_prog = bpf_program__fd(p);
	xdp_cfg_reset();
	return 0;
}

void xdp_close(void)
{
	if (g_obj != NULL)
		bpf_object__close(g_obj);
	g_obj = NULL;
	g_prog = -1;
}

int xdp_status(char *why, size_t cap)
{
	if (geteuid() != 0)
		return 1;
	return xdp_open(why, cap) == 0 ? 0 : -1;
}

int xdp_run(const void *pkt, size_t len, uint32_t *action)
{
	uint8_t out[2048];
	LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = pkt, .data_size_in = (__u32)len, .data_out = out,
		    .data_size_out = sizeof out, .repeat = 1);
	if (bpf_prog_test_run_opts(g_prog, &o) != 0)
		return -errno;
	*action = o.retval;
	return 0;
}

int xdp_map_fd(const char *name)
{
	struct bpf_map *m = bpf_object__find_map_by_name(g_obj, name);
	return m == NULL ? -1 : bpf_map__fd(m);
}

void xdp_cfg_get(struct bst_xdp_config *c)
{
	uint32_t k = 0;
	memset(c, 0, sizeof *c);
	(void)bpf_map_lookup_elem(xdp_map_fd("cfg"), &k, c);
}

void xdp_cfg_set(const struct bst_xdp_config *c)
{
	uint32_t k = 0;
	if (bpf_map_update_elem(xdp_map_fd("cfg"), &k, c, BPF_ANY) != 0)
		abort();
}

void xdp_cfg_reset(void)
{
	struct bst_xdp_config c;
	memset(&c, 0, sizeof c);
	c.flags = BST_XDP_F_DROP_BAD_TCP_FLAGS;
	c.v6_prefix = 64;
	xdp_cfg_set(&c);
}

void xdp_cfg_protect_443(struct bst_xdp_config *c)
{
	c->tcp_ports[0] = 443;
	c->ntcp = 1;
	c->udp_ports[0] = 443;
	c->nudp = 1;
}

uint64_t xdp_stat(uint32_t reason)
{
	int n = libbpf_num_possible_cpus();
	if (n <= 0)
		return 0;
	uint64_t *v = calloc((size_t)n, sizeof *v), sum = 0;
	if (v == NULL)
		abort();
	if (bpf_map_lookup_elem(xdp_map_fd("stats"), &reason, v) == 0)
		for (int i = 0; i < n; i++)
			sum += v[i];
	free(v);
	return sum;
}

void xdp_stats_reset(void)
{
	int n = libbpf_num_possible_cpus();
	uint64_t *v = calloc((size_t)(n > 0 ? n : 1), sizeof *v);
	if (v == NULL)
		abort();
	for (uint32_t r = 0; r < BST_XDP_NREASONS; r++)
		(void)bpf_map_update_elem(xdp_map_fd("stats"), &r, v, BPF_ANY);
	free(v);
}

int xdp_map_set_list(const char *map, const char *text)
{
	bst_cidr c;
	if (!bst_cidr_parse((bst_str){ text, (uint32_t)strlen(text) }, &c))
		return -1;
	bst_ip ip = c.ip;
	int fd = xdp_map_fd(map);
	uint8_t one = 1;
	if (ip.family == BST_IP_V4) {
		struct bst_xdp_lpm4 k = { .prefixlen = c.prefix };
		memcpy(k.addr, ip.b, 4);
		return bpf_map_update_elem(fd, &k, &one, BPF_ANY);
	}
	struct bst_xdp_lpm6 k = { .prefixlen = c.prefix };
	memcpy(k.addr, ip.b, 16);
	return bpf_map_update_elem(fd, &k, &one, BPF_ANY);
}

int xdp_map_clear(const char *map)
{
	int fd = xdp_map_fd(map);
	uint8_t key[64], next[64];
	while (bpf_map_get_next_key(fd, NULL, next) == 0) {
		memcpy(key, next, sizeof key);
		if (bpf_map_delete_elem(fd, key) != 0)
			return -1;
	}
	return 0;
}

int xdp_map_set_dyn(const char *addr, unsigned prefix, uint64_t expires_ns)
{
	uint8_t b[16];
	if (inet_pton(AF_INET, addr, b) == 1)
		return bpf_map_update_elem(xdp_map_fd("dyn_block4"), b, &expires_ns, BPF_ANY);
	if (inet_pton(AF_INET6, addr, b) != 1)
		return -1;
	struct bst_xdp_dyn6 k;
	memset(&k, 0, sizeof k);
	k.prefix = (uint8_t)prefix;
	for (unsigned i = 0; i < 16; i++) {
		unsigned bits = prefix > i * 8 ? prefix - i * 8 : 0;
		k.addr[i] = bits >= 8 ? b[i] : (uint8_t)(b[i] & (0xff00u >> bits));
	}
	return bpf_map_update_elem(xdp_map_fd("dyn_block6"), &k, &expires_ns, BPF_ANY);
}

/* ---- packet builders ---- */

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

/* Ethernet header and tags; returns the offset of the L3 header. */
static size_t eth(uint8_t *b, int vlans, uint16_t type)
{
	static const uint8_t dst[6] = { 2, 0, 0, 0, 0, 2 }, src[6] = { 2, 0, 0, 0, 0, 1 };
	memcpy(b, dst, 6);
	memcpy(b + 6, src, 6);
	size_t off = 12;
	for (int i = 0; i < vlans; i++) {
		put16(b + off, i == 0 && vlans == 2 ? 0x88a8 : 0x8100);
		put16(b + off + 2, (uint16_t)(100 + i));
		off += 4;
	}
	put16(b + off, type);
	return off + 2;
}

static size_t ip4(uint8_t *b, size_t cap, const pkt_opts *o, uint8_t proto, size_t l4len)
{
	pkt_opts d = { 0 };
	if (o == NULL)
		o = &d;
	size_t off = eth(b, o->vlans, 0x0800);
	if (off + 20 + l4len > cap)
		abort();
	uint8_t *h = b + off;
	memset(h, 0, 20);
	h[0] = 0x45;
	put16(h + 2, (uint16_t)(20 + l4len));
	put16(h + 6, o->frag_off);
	h[8] = 64;
	h[9] = o->proto_override ? o->proto_override : proto;
	if (inet_pton(AF_INET, o->src ? o->src : "192.0.2.1", h + 12) != 1 ||
	    inet_pton(AF_INET, o->dst ? o->dst : "198.51.100.1", h + 16) != 1)
		abort();
	return off + 20;
}

static size_t ip6(uint8_t *b, size_t cap, const pkt_opts *o, uint8_t proto, size_t l4len)
{
	pkt_opts d = { 0 };
	if (o == NULL)
		o = &d;
	size_t off = eth(b, o->vlans, 0x86dd);
	size_t ext = (size_t)o->v6_ext * 8 + (o->v6_frag ? 8 : 0);
	if (off + 40 + ext + l4len > cap)
		abort();
	uint8_t *h = b + off;
	memset(h, 0, 40);
	h[0] = 0x60;
	put16(h + 4, (uint16_t)(ext + l4len));
	h[7] = 64;
	if (inet_pton(AF_INET6, o->src ? o->src : "2001:db8::1", h + 8) != 1 ||
	    inet_pton(AF_INET6, o->dst ? o->dst : "2001:db8::2", h + 24) != 1)
		abort();
	uint8_t final = o->proto_override ? o->proto_override : proto;
	uint8_t *next = h + 6;
	size_t at = off + 40;
	for (int i = 0; i < o->v6_ext; i++) {
		*next = i == 0 ? 0 : 60; /* hop-by-hop first, then destination options */
		memset(b + at, 0, 8);
		b[at + 2] = 1; /* PadN option filling the header */
		b[at + 3] = 4;
		next = b + at;
		at += 8;
	}
	if (o->v6_frag) {
		*next = 44;
		memset(b + at, 0, 8);
		put16(b + at + 2, (uint16_t)((o->v6_frag_off << 3) | (o->v6_frag_more ? 1 : 0)));
		next = b + at;
		at += 8;
	}
	*next = final;
	return at;
}

static size_t tcp(uint8_t *b, size_t at, const pkt_opts *o)
{
	pkt_opts d = { 0 };
	if (o == NULL)
		o = &d;
	uint8_t *t = b + at;
	memset(t, 0, 20);
	put16(t, o->sport ? o->sport : 40000);
	put16(t + 2, o->dport ? o->dport : 443);
	t[12] = 5 << 4;
	t[13] = o->flags_zero ? 0 : o->tcp_flags ? o->tcp_flags : TCP_F_SYN;
	put16(t + 14, 65535);
	if (o->payload) {
		if (o->data)
			memcpy(t + 20, o->data, o->payload);
		else
			memset(t + 20, 0, o->payload);
	}
	return at + 20 + o->payload;
}

static size_t udp(uint8_t *b, size_t at, const pkt_opts *o)
{
	pkt_opts d = { 0 };
	if (o == NULL)
		o = &d;
	uint8_t *u = b + at;
	put16(u, o->sport ? o->sport : 40000);
	put16(u + 2, o->dport ? o->dport : 443);
	put16(u + 4, (uint16_t)(8 + o->payload));
	put16(u + 6, 0);
	if (o->payload) {
		if (o->data)
			memcpy(u + 8, o->data, o->payload);
		else
			memset(u + 8, 0, o->payload);
	}
	return at + 8 + o->payload;
}

static size_t payload(const pkt_opts *o)
{
	return o ? o->payload : 0;
}

size_t pkt_tcp4(uint8_t *b, size_t cap, const pkt_opts *o)
{
	return tcp(b, ip4(b, cap, o, 6, 20 + payload(o)), o);
}

size_t pkt_tcp6(uint8_t *b, size_t cap, const pkt_opts *o)
{
	return tcp(b, ip6(b, cap, o, 6, 20 + payload(o)), o);
}

size_t pkt_udp4(uint8_t *b, size_t cap, const pkt_opts *o)
{
	return udp(b, ip4(b, cap, o, 17, 8 + payload(o)), o);
}

size_t pkt_udp6(uint8_t *b, size_t cap, const pkt_opts *o)
{
	return udp(b, ip6(b, cap, o, 17, 8 + payload(o)), o);
}

size_t pkt_icmp4(uint8_t *b, size_t cap, const pkt_opts *o)
{
	size_t at = ip4(b, cap, o, 1, 8);
	memset(b + at, 0, 8);
	b[at] = 3; /* destination unreachable */
	b[at + 1] = 4; /* fragmentation needed: PMTUD */
	return at + 8;
}

size_t pkt_icmp6(uint8_t *b, size_t cap, const pkt_opts *o)
{
	size_t at = ip6(b, cap, o, 58, 8);
	memset(b + at, 0, 8);
	b[at] = 2; /* packet too big */
	return at + 8;
}

size_t pkt_arp(uint8_t *b, size_t cap)
{
	if (cap < 42)
		abort();
	size_t at = eth(b, 0, 0x0806);
	memset(b + at, 0, 28);
	put16(b + at, 1);
	put16(b + at + 2, 0x0800);
	b[at + 4] = 6;
	b[at + 5] = 4;
	put16(b + at + 6, 1);
	return at + 28;
}

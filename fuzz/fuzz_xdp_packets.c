/* libFuzzer harness for the XDP filter (src/xdp/xdp_bastion.bpf.c): random frames run through the
 * loaded program with BPF_PROG_TEST_RUN. The verifier already proves every packet read is in
 * bounds; this checks the property it can not: whatever the bytes and the configuration, the
 * program returns XDP_PASS, XDP_DROP or XDP_TX (SYN cookie replies) and never aborts.
 *
 * Input: the first byte picks config flags and whether port 443 is protected (and QUIC on it), a
 * second byte turns the rate limits on; the rest is the frame. Needs root (CAP_BPF): without it,
 * or when the object does not load, the harness aborts at once, so a smoke run can not pass
 * without testing anything. */
#include "xdp/xdp_common.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const unsigned char bst_embed_xdp_bastion[];
extern const unsigned char bst_embed_xdp_bastion_end[];

static int g_prog = -1, g_cfg = -1;
static struct bpf_object *g_obj; /* loaded once, kept for the whole run */

static int quiet(enum libbpf_print_level l, const char *f, va_list ap)
{
	(void)l, (void)f, (void)ap;
	return 0;
}

static void load(void)
{
	libbpf_set_print(quiet);
	size_t len = (size_t)(bst_embed_xdp_bastion_end - bst_embed_xdp_bastion);
	LIBBPF_OPTS(bpf_object_open_opts, oo, .object_name = "bst_xdp_fuzz");
	struct bpf_object *o = bpf_object__open_mem(bst_embed_xdp_bastion, len, &oo);
	if (o == NULL || bpf_object__load(o) != 0) {
		fprintf(stderr, "fuzz_xdp_packets: the XDP object did not load (root needed)\n");
		abort();
	}
	g_obj = o;
	g_prog = bpf_program__fd(bpf_object__find_program_by_name(o, "bst_xdp"));
	g_cfg = bpf_map__fd(bpf_object__find_map_by_name(o, "cfg"));
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (g_prog < 0)
		load();
	if (size < 2 || size > 4096)
		return 0;
	struct bst_xdp_config c;
	memset(&c, 0, sizeof c);
	c.flags = d[0] & 0x3fu;
	c.v6_prefix = 64;
	if (d[0] & 0x40u) {
		c.tcp_ports[0] = c.udp_ports[0] = 443;
		c.ntcp = c.nudp = 1;
	}
	if (d[0] & 0x80u) {
		c.quic_ports[0] = 443;
		c.nquic = 1;
		c.flags |= BST_XDP_F_QUIC_CHECK;
		c.refl_ports[0] = 53;
		c.nrefl = 1;
	}
	if (d[1] & 1u) {
		c.syn_rate = c.udp_rate = c.pps_rate = 10;
		c.syn_burst = c.udp_burst = c.pps_burst = 2;
		c.auto_after = (d[1] & 2u) ? 3 : 0;
		c.auto_ns = 1000000000ull;
	}
	uint32_t k = 0;
	if (bpf_map_update_elem(g_cfg, &k, &c, BPF_ANY) != 0)
		abort();
	uint8_t out[4200];
	LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = d + 2, .data_size_in = (uint32_t)(size - 2),
		    .data_out = out, .data_size_out = sizeof out, .repeat = 1);
	if (bpf_prog_test_run_opts(g_prog, &o) != 0)
		return 0; /* the kernel refuses frames shorter than an Ethernet header */
	if (o.retval != XDP_PASS && o.retval != XDP_DROP && o.retval != XDP_TX)
		abort();
	return 0;
}

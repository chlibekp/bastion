/* XDP filter statistics (Phase 13, Task 9): the per-CPU `stats` map summed, and master's 1 Hz
 * poll that turns it into the bastion_xdp_packets_total{reason} counters and an `xdp: stats` log
 * line whenever a drop count moved (at most one a second, so a flood can not flood the log). */
#include "xdp/loader.h"

#include "core/counters.h"
#include "core/log.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const reason_names[BST_XDP_NREASONS] = {
	"pass", "allow", "non_ip", "malformed", "tcp_flags", "fragment", "deny", "blocked",
	"unprotected", "syn_rate", "udp_rate", "pps_rate", "reflection", "quic", "v6_ext", "auto_blocked",
};

const char *bst_xdp_reason_name(unsigned r)
{
	return r < BST_XDP_NREASONS ? reason_names[r] : "?";
}

int bst_xdp_read_stats(bst_xdp *x, bst_xdp_stats *out)
{
	memset(out, 0, sizeof *out);
	int ncpu = libbpf_num_possible_cpus();
	if (ncpu <= 0 || ncpu > 4096)
		return -1;
	uint64_t *v = calloc((size_t)ncpu, sizeof *v);
	if (v == NULL)
		return -1;
	int fd = bst_xdp_map_fd(x, "stats"), rc = 0;
	for (uint32_t k = 0; k < BST_XDP_NREASONS; k++) {
		if (bpf_map_lookup_elem(fd, &k, v) != 0) {
			rc = -1;
			continue;
		}
		for (int c = 0; c < ncpu; c++)
			out->n[k] += v[c];
	}
	free(v);
	return rc;
}

static bst_counter_id g_ctr[BST_XDP_NREASONS];
static bst_xdp_stats g_last;
static bool g_ready;

void bst_xdp_stats_setup(bst_xdp *x)
{
	static char labels[BST_XDP_NREASONS][32];
	for (unsigned r = 0; r < BST_XDP_NREASONS; r++) {
		snprintf(labels[r], sizeof labels[r], "reason=%s", reason_names[r]);
		g_ctr[r] = bst_counter_register("bastion_xdp_packets_total",
						"packets the XDP filter passed or dropped, by reason", labels[r]);
	}
	/* an adopted filter's counts start where the previous master left them */
	g_ready = bst_xdp_read_stats(x, &g_last) == 0;
}

void bst_xdp_stats_poll(bst_xdp *x)
{
	bst_xdp_stats now;
	if (bst_xdp_read_stats(x, &now) != 0)
		return;
	bool moved = false;
	for (unsigned r = 0; r < BST_XDP_NREASONS; r++) {
		uint64_t d = g_ready && now.n[r] >= g_last.n[r] ? now.n[r] - g_last.n[r] : 0;
		if (d > 0 && g_ctr[r] != BST_COUNTER_INVALID)
			bst_counter_add(g_ctr[r], d);
		if (d > 0 && r >= BST_XDP_DROP_MALFORMED)
			moved = true;
	}
	g_last = now;
	g_ready = true;
	if (!moved)
		return;
	char line[1024];
	size_t o = 0;
	for (unsigned r = 0; r < BST_XDP_NREASONS && o < sizeof line; r++)
		o += (size_t)snprintf(line + o, sizeof line - o, "%s%s=%llu", r ? " " : "", reason_names[r],
				      (unsigned long long)now.n[r]);
	bst_log(BST_LOG_INFO, "xdp: stats %s", line);
}

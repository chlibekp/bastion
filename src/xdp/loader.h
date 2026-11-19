/* The XDP filter's loader and lifecycle (Phase 13, architecture section 7).
 *
 * Master loads the embedded object (xdp/xdp_bastion.bpf.c), fills its maps from the `xdp {}`
 * block and attaches it to every `interface` with a bpf_link. Master is the only process with
 * bpf(): workers ask for blocks through their escalation ring (sec/block.h, xdp/block.h).
 *
 * Modes: `auto` tries native (driver) then generic; `native`, `generic` and `hw` ask for that
 * one, falling back to generic with a warning unless `require` is given, which makes a refusal
 * a startup error. `hw` is offload to the NIC: untested without such hardware.
 *
 * Pinning and ownership: when pin_path is on a bpffs mount, each interface's link is pinned at
 * <pin_path>/link_<ifname> and every map at <pin_path>/<map>. A pinned link outlives the
 * process, so a crash (kill -9) leaves the filter running with its last maps, never an interface
 * dropping traffic under a program nobody owns: the next start adopts it, reusing the pinned
 * maps and swapping its own program in (bpf_link_update), with no detach gap. That is also how a
 * Phase 14 upgrade hands the filter to the new master. On a clean stop, `on_exit detach` removes
 * pins and links (traffic is no longer filtered); `on_exit keep` leaves them (the filter keeps
 * running with its static lists; dynamic blocks expire by their TTL). Without bpffs nothing is
 * pinned and the links die with master, whatever on_exit says (logged).
 *
 * Without privilege (no CAP_BPF/CAP_NET_ADMIN, as in an unprivileged container), a kernel
 * without XDP, or a mode a driver refuses, master logs a warning and runs without the filter:
 * every L7 limit still applies. Only `mode ... require` turns such a failure into an error. */
#ifndef BST_XDP_LOADER_H
#define BST_XDP_LOADER_H

#include "core/cidr.h"
#include "core/err.h"
#include "xdp/xdp_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_XDP_MAX_IFACES 8

typedef enum bst_xdp_mode { BST_XDP_AUTO = 0, BST_XDP_NATIVE, BST_XDP_GENERIC, BST_XDP_HW } bst_xdp_mode;

/* The `xdp {}` block, compiled. Absent block: cfg->global.xdp is NULL and no BPF is loaded. */
typedef struct bst_cfg_xdp {
	const char *ifaces[BST_XDP_MAX_IFACES];
	size_t nifaces;
	bst_xdp_mode mode;
	bool require;	  /* a mode refusal is a startup error */
	const char *pin_path; /* default /sys/fs/bpf/bastion */
	bool on_exit_keep;
	bst_cidr *allow, *deny; /* `allow`, `deny` and the entries of their _file forms */
	size_t nallow, ndeny, allow_cap_, deny_cap_;
	unsigned ipv6_prefix; /* 48, 56, 64 (default) or 128 */
	uint32_t flags;	      /* BST_XDP_F_* */
	uint16_t refl_ports[BST_XDP_MAX_REFL_PORTS];
	size_t nrefl;
	uint64_t syn_rate, syn_burst, udp_rate, udp_burst, pps_rate, pps_burst; /* totals, per second */
	unsigned auto_after;
	uint64_t auto_ns;
	unsigned dyn_size; /* dyn_block map entries (escalation_ceiling, at least 1024) */
	/* Filled from the listeners by the config post hook: TCP ports of plain and TLS listeners,
	 * UDP (and QUIC) ports of `http3` listeners. */
	uint16_t tcp_ports[BST_XDP_MAX_PORTS], udp_ports[BST_XDP_MAX_PORTS];
	size_t ntcp, nudp;
} bst_cfg_xdp;

typedef struct bst_xdp bst_xdp;

/* Loads, fills and attaches. NULL with err set when nothing could be attached (the caller
 * decides: an error under `require`, else a warning). A partial failure (one of several
 * interfaces) is an error too, after undoing the others. */
bst_xdp *bst_xdp_load(const bst_cfg_xdp *cfg, bst_err *err);

/* Rewrites the config map and the static lists from cfg without detaching: new list entries
 * go in before stale ones come out, so no address is ever unfiltered in between. 0 or -1. */
int bst_xdp_reconfigure(bst_xdp *x, const bst_cfg_xdp *cfg, bst_err *err);

/* Ends master's ownership as `on_exit` says (see above) and frees x. */
void bst_xdp_detach(bst_xdp *x);
/* A live upgrade (proc/upgrade.h): the other master owns the pinned links and maps now, so the
 * next bst_xdp_detach leaves them whatever `on_exit` says. Unpinned links still die with us. */
void bst_xdp_hand_over(bst_xdp *x);
/* A rollback: swaps our program back into our links (bpf_link_update), with no detach gap.
 * 0, or -1 when an interface could not be taken back (logged). */
int bst_xdp_take_back(bst_xdp *x);

/* How many interface links are pinned under pin_path (0 when none, or no bpffs there). */
int bst_xdp_adopt_pinned(const char *pin_path);

/* The mode each interface got ("native", "generic", "hw"), for logs and tests. */
const char *bst_xdp_mode_of(const bst_xdp *x, size_t iface);

/* A map's fd ("dyn_block4", ...) for the block backend and the stats reader; -1 if unknown. */
int bst_xdp_map_fd(const bst_xdp *x, const char *name);

/* Per-reason drop and pass counts summed over CPUs (Task 9). */
typedef struct bst_xdp_stats {
	uint64_t n[BST_XDP_NREASONS];
} bst_xdp_stats;
int bst_xdp_read_stats(bst_xdp *x, bst_xdp_stats *out);

/* The reason's metric label ("malformed", "deny", ...). */
const char *bst_xdp_reason_name(unsigned reason);

/* Master (xdp/stats.c): registers bastion_xdp_packets_total{reason} (before any fork), then
 * bst_xdp_stats_poll at 1 Hz adds what moved and logs an `xdp: stats` line when drops did. */
void bst_xdp_stats_setup(bst_xdp *x);
void bst_xdp_stats_poll(bst_xdp *x);

#endif

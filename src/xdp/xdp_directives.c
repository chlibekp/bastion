/* The `xdp {}` block (Phase 13): the XDP filter's interfaces, attach mode, lifecycle, static lists
 * and packet rules. See xdp/loader.h for what each does at run time. An absent block loads no BPF
 * at all; that is why it is not a singleton (a singleton is synthesised when absent). */
#include "config/compile.h"
#include "config/errfmt.h"
#include "config/values.h"
#include "core/arena.h"
#include "core/addr.h"
#include "io/listener.h"
#include "sec/block.h"
#include "xdp/loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XC BST_CTX_XDP
#define ONE(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static int oom(bst_err *e)
{
	bst_err_set(e, "out of memory");
	return -1;
}

static bst_cfg_xdp *X(bst_cfg_ctx *c)
{
	return c->global->xdp;
}

/* Amplification source ports: DNS, NTP, CLDAP, SSDP, memcached, chargen, SNMP, Portmap, NetBIOS,
 * mDNS, WS-Discovery, ARMS, CoAP, Ubiquiti discovery. */
static const uint16_t default_refl[] = { 53, 123, 389, 1900, 11211, 19, 161, 111, 137, 5353, 3702, 3283, 5683, 10001 };

static int ap_xdp(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)d, (void)n;
	bst_cfg_xdp *x = bst_arena_alloc(c->arena, sizeof *x);
	if (x == NULL)
		return oom(e);
	memset(x, 0, sizeof *x);
	x->pin_path = "/sys/fs/bpf/bastion";
	x->ipv6_prefix = 64;
	x->flags = BST_XDP_F_DROP_BAD_TCP_FLAGS | BST_XDP_F_DROP_REFLECTION | BST_XDP_F_QUIC_CHECK;
	memcpy(x->refl_ports, default_refl, sizeof default_refl);
	x->nrefl = sizeof default_refl / sizeof *default_refl;
	x->auto_ns = 10ull * 1000000000ull;
	c->global->xdp = x;
	return 0;
}

static int ap_interface(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_xdp *x = X(c);
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		if (x->nifaces == BST_XDP_MAX_IFACES || a->len >= 16) {
			bst_err_set(e, x->nifaces == BST_XDP_MAX_IFACES ? "interface: at most %d" : "interface: name too long",
				    BST_XDP_MAX_IFACES);
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		const char *s = bst_cfg_strdup(c, a->text, a->len, e);
		if (s == NULL)
			return -1;
		x->ifaces[x->nifaces++] = s;
	}
	return 0;
}

static const char *const modes[] = { "auto", "native", "generic", "hw", NULL };

static int ap_mode(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	size_t idx = 0;
	(void)bst_parse_enum(as_str(bst_dir_pos(d, n, 0)), modes, &idx);
	X(c)->mode = (bst_xdp_mode)idx;
	if (bst_dir_npos(d, n) > 1) {
		const bst_ast_arg *a = bst_dir_pos(d, n, 1);
		if (!bst_str_eq(as_str(a), BST_S("require"))) {
			bst_err_set(e, "mode: the second word can only be `require`");
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		X(c)->require = true;
	}
	return 0;
}

static int ap_pin_path(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	if (a->len == 0 || a->text[0] != '/' || a->len > 150) {
		bst_err_set(e, "pin_path: an absolute path of at most 150 bytes");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	X(c)->pin_path = bst_cfg_strdup(c, a->text, a->len, e);
	return X(c)->pin_path == NULL ? -1 : 0;
}

static int ap_on_exit(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	X(c)->on_exit_keep = bst_str_eq(as_str(bst_dir_pos(d, n, 0)), BST_S("keep"));
	return 0;
}

static int push(bst_cfg_ctx *c, bool allow, const bst_cidr *x, bst_err *e)
{
	bst_cfg_xdp *xc = X(c);
	if (allow)
		return bst_cfg_push_owned(c, &xc->allow, &xc->nallow, &xc->allow_cap_, sizeof *x, x, e);
	return bst_cfg_push_owned(c, &xc->deny, &xc->ndeny, &xc->deny_cap_, sizeof *x, x, e);
}

/* "addr" or "addr/len" into x; false when it is neither. */
static bool cidr_of(bst_str s, bst_cidr *x)
{
	if (bst_cidr_parse(s, x))
		return true;
	bst_ip ip;
	if (!bst_addr_parse(s, &ip))
		return false;
	x->ip = ip;
	x->prefix = ip.family == BST_IP_V4 ? 32 : 128;
	return true;
}

static int ap_list(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bool allow = strcmp(d->name, "allow") == 0;
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		bst_cidr x;
		if (!cidr_of(as_str(a), &x)) {
			bst_err_set(e, "%s: not an address or CIDR", d->name);
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		if (push(c, allow, &x, e) != 0)
			return -1;
	}
	return 0;
}

/* One address or CIDR per line; '#' starts a comment; blank lines are skipped. */
static int ap_list_file(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	char path[4096];
	if (a->len >= sizeof path) {
		bst_err_set(e, "%s: path too long", d->name);
		return -1;
	}
	memcpy(path, a->text, a->len);
	path[a->len] = '\0';
	FILE *f = fopen(path, "re");
	if (f == NULL) {
		bst_err_set(e, "%s: can not open '%s': %m", d->name, path);
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	bool allow = strcmp(d->name, "allow_file") == 0;
	char line[256];
	unsigned no = 0;
	int rc = 0;
	while (rc == 0 && fgets(line, sizeof line, f) != NULL) {
		no++;
		char *h = strchr(line, '#');
		if (h != NULL)
			*h = '\0';
		char *s = line;
		while (*s == ' ' || *s == '\t')
			s++;
		size_t len = strcspn(s, " \t\r\n");
		if (len == 0)
			continue;
		bst_cidr x;
		if (!cidr_of((bst_str){ s, (uint32_t)len }, &x)) {
			bst_err_set(e, "%s: '%s' line %u: not an address or CIDR", d->name, path, no);
			bst_cfg_err_at(e, &a->loc);
			rc = -1;
		} else {
			rc = push(c, allow, &x, e);
		}
	}
	fclose(f);
	return rc;
}

static int ap_v6p(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	int64_t v = 64;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	(void)bst_parse_int(as_str(a), 48, 128, &v);
	if (v != 48 && v != 56 && v != 64 && v != 128) {
		bst_err_set(e, "ipv6_prefix: 48, 56, 64 or 128");
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	X(c)->ipv6_prefix = (unsigned)v;
	return 0;
}

static uint32_t flag_of(const char *name)
{
	if (strcmp(name, "drop_fragments") == 0)
		return BST_XDP_F_DROP_FRAGMENTS;
	if (strcmp(name, "drop_bad_tcp_flags") == 0)
		return BST_XDP_F_DROP_BAD_TCP_FLAGS;
	if (strcmp(name, "drop_unprotected") == 0)
		return BST_XDP_F_DROP_UNPROTECTED;
	if (strcmp(name, "drop_reflection") == 0)
		return BST_XDP_F_DROP_REFLECTION;
	if (strcmp(name, "drop_v6_ext") == 0)
		return BST_XDP_F_DROP_V6_EXT;
	return BST_XDP_F_QUIC_CHECK;
}

static int ap_flag(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool b = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &b);
	uint32_t f = flag_of(d->name);
	X(c)->flags = b ? X(c)->flags | f : X(c)->flags & ~f;
	return 0;
}

static int ap_refl_ports(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_xdp *x = X(c);
	x->nrefl = 0;
	for (size_t i = 0; i < bst_dir_npos(d, n); i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		int64_t p = 0;
		if (x->nrefl == BST_XDP_MAX_REFL_PORTS || !bst_parse_int(as_str(a), 1, 65535, &p)) {
			bst_err_set(e, "reflection_ports: up to %d ports of 1-65535", BST_XDP_MAX_REFL_PORTS);
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		x->refl_ports[x->nrefl++] = (uint16_t)p;
	}
	return 0;
}

static const bst_optspec burst_opt[] = {
	{ .key = "burst=", .type = { .kind = BST_T_INT, .min = 1, .max = 100000000 } },
};

static int ap_rate(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_rate r;
	const bst_ast_arg *a = bst_dir_pos(d, n, 0);
	(void)bst_parse_rate(as_str(a), &r);
	uint64_t per_s = r.period_us > 0 ? r.count * 1000000u / r.period_us : 0;
	if (per_s == 0) {
		bst_err_set(e, "%s: at least 1/s", d->name);
		bst_cfg_err_at(e, &a->loc);
		return -1;
	}
	uint64_t burst = per_s;
	bst_ast_arg v;
	if (bst_dir_opt(d, n, "burst=", &v)) {
		int64_t b = 1;
		(void)bst_parse_int(as_str(&v), 1, 100000000, &b);
		burst = (uint64_t)b;
	}
	bst_cfg_xdp *x = X(c);
	if (d->name[0] == 's') {
		x->syn_rate = per_s;
		x->syn_burst = burst;
	} else if (d->name[0] == 'u') {
		x->udp_rate = per_s;
		x->udp_burst = burst;
	} else {
		x->pps_rate = per_s;
		x->pps_burst = burst;
	}
	return 0;
}

static const bst_optspec auto_opts[] = {
	{ .key = "after=", .type = { .kind = BST_T_INT, .min = 1, .max = 1000000 } },
	{ .key = "for=", .type = { .kind = BST_T_DURATION, .min = 1000000, .max = 3600ll * 1000000 } },
};

static int ap_auto_block(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	bst_cfg_xdp *x = X(c);
	if (bst_dir_npos(d, n) == 1 && bst_str_eq(as_str(bst_dir_pos(d, n, 0)), BST_S("off"))) {
		x->auto_after = 0;
		return 0;
	}
	bst_ast_arg v;
	int64_t after = 0;
	if (bst_dir_npos(d, n) != 0 || !bst_dir_opt(d, n, "after=", &v) || !bst_parse_int(as_str(&v), 1, 1000000, &after)) {
		bst_err_set(e, "auto_block: off, or after=<drops> [for=<duration>]");
		bst_cfg_err_at(e, &n->loc);
		return -1;
	}
	x->auto_after = (unsigned)after;
	uint64_t us = 10000000;
	if (bst_dir_opt(d, n, "for=", &v))
		(void)bst_parse_duration_us(as_str(&v), &us);
	x->auto_ns = us * 1000u;
	return 0;
}

/* Protected ports from the listeners, and the dynamic map size from escalation_ceiling. */
static int post_xdp(bst_config *cfg, bst_cfg_ctx *c, bst_err *e)
{
	(void)c;
	bst_cfg_xdp *x = cfg->global.xdp;
	if (x == NULL)
		return 0;
	if (x->nifaces == 0) {
		bst_err_set(e, "xdp: needs at least one `interface`");
		return -1;
	}
	unsigned ceil = cfg->global.escalation_ceiling > 0 ? cfg->global.escalation_ceiling : BST_BLOCK_CEILING_DEFAULT;
	x->dyn_size = ceil < 1024 ? 1024 : ceil;
	const bst_cfg_listen **ls = NULL;
	size_t nl = 0;
	if (bst_config_listeners(cfg, &ls, &nl, e) != 0)
		return -1;
	int rc = 0;
	for (size_t i = 0; i < nl && rc == 0; i++) {
		uint16_t p = ls[i]->addr.port;
		uint16_t *v = ls[i]->http3 ? x->udp_ports : x->tcp_ports;
		size_t *nv = ls[i]->http3 ? &x->nudp : &x->ntcp;
		bool have = false;
		for (size_t j = 0; j < *nv; j++)
			have |= v[j] == p;
		if (have || p == 0)
			continue;
		if (*nv == BST_XDP_MAX_PORTS) {
			bst_err_set(e, "xdp: more than %d listening %s ports", BST_XDP_MAX_PORTS, ls[i]->http3 ? "UDP" : "TCP");
			rc = -1;
			break;
		}
		v[(*nv)++] = p;
	}
	free(ls);
	return rc;
}
BST_CFG_POST(post_xdp);

static const bst_directive xdp_dirs[] = {
	{ .name = "xdp", .contexts = BST_CTX_GLOBAL, .apply = ap_xdp, .child_ctx = XC,
	  .doc = "The XDP DDoS filter: drops attack traffic in the driver (or the generic hook) before "
		 "the network stack. Master loads and attaches it; workers never touch it. Without "
		 "this block no BPF is loaded. Without the privilege (CAP_BPF and CAP_NET_ADMIN) or "
		 "kernel support, a warning is logged and every L7 limit still applies.",
	  .args = { .block = BST_BLOCK_REQUIRED } },
	{ .name = "interface", .contexts = XC, .apply = ap_interface, .repeatable = true,
	  .doc = "A network interface to attach to (repeatable; up to 8).",
	  .args = { .min_args = 1, .max_args = BST_XDP_MAX_IFACES, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "mode", .contexts = XC, .apply = ap_mode,
	  .doc = "auto (default: native, else generic), native, generic or hw (NIC offload, untested "
		 "without such a NIC). A refused mode falls back to generic with a warning; with "
		 "`require` it is a startup error instead.",
	  .args = { .min_args = 1, .max_args = 2,
		    .pos = { { .kind = BST_T_ENUM, .enum_values = modes }, { .kind = BST_T_STRING } } } },
	{ .name = "pin_path", .contexts = XC, .apply = ap_pin_path,
	  .doc = "Directory on a bpffs mount for the pinned links and maps (default "
		 "/sys/fs/bpf/bastion). A pinned filter survives a crash and is adopted by the next "
		 "start, with no detach gap.",
	  ONE({ .kind = BST_T_PATH }) },
	{ .name = "on_exit", .contexts = XC, .apply = ap_on_exit,
	  .doc = "On a clean stop: detach (default) removes the filter; keep leaves it running with "
		 "its lists until the next start adopts it.",
	  ONE({ .kind = BST_T_ENUM, .enum_values = (const char *const[]){ "detach", "keep", NULL } }) },
	{ .name = "allow", .contexts = XC, .apply = ap_list, .repeatable = true,
	  .doc = "Sources never dropped: every later check is skipped, and escalation never blocks "
		 "them. Allow wins over deny.",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "deny", .contexts = XC, .apply = ap_list, .repeatable = true,
	  .doc = "Sources always dropped (longest prefix match).",
	  .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "allow_file", .contexts = XC, .apply = ap_list_file, .repeatable = true,
	  .doc = "allow, one address or CIDR per line of the file ('#' comments).",
	  ONE({ .kind = BST_T_PATH }) },
	{ .name = "deny_file", .contexts = XC, .apply = ap_list_file, .repeatable = true,
	  .doc = "deny, one address or CIDR per line of the file ('#' comments).",
	  ONE({ .kind = BST_T_PATH }) },
	{ .name = "ipv6_prefix", .contexts = XC, .apply = ap_v6p,
	  .doc = "IPv6 sources share rate buckets and auto blocks by this prefix: 48, 56, 64 "
		 "(default) or 128.",
	  ONE({ .kind = BST_T_INT, .min = 48, .max = 128 }) },
	{ .name = "drop_fragments", .contexts = XC, .apply = ap_flag,
	  .doc = "Drop IP fragments (off by default: non-first fragments, which can not be port "
		 "matched, pass).",
	  ONE({ .kind = BST_T_BOOL }) },
	{ .name = "drop_bad_tcp_flags", .contexts = XC, .apply = ap_flag,
	  .doc = "Drop null, xmas, SYN+FIN and SYN+RST segments to protected ports (on by default).",
	  ONE({ .kind = BST_T_BOOL }) },
	{ .name = "drop_unprotected", .contexts = XC, .apply = ap_flag,
	  .doc = "Drop TCP and UDP to ports Bastion does not listen on (off by default).",
	  ONE({ .kind = BST_T_BOOL }) },
	{ .name = "drop_v6_ext", .contexts = XC, .apply = ap_flag,
	  .doc = "Drop IPv6 packets with more than 6 extension headers (off by default: they pass).",
	  ONE({ .kind = BST_T_BOOL }) },
	{ .name = "drop_reflection", .contexts = XC, .apply = ap_flag,
	  .doc = "Drop UDP from amplification source ports (reflection_ports) to protected ports (on "
		 "by default). Replies to Bastion's own queries go to ephemeral ports: unaffected.",
	  ONE({ .kind = BST_T_BOOL }) },
	{ .name = "reflection_ports", .contexts = XC, .apply = ap_refl_ports,
	  .doc = "The amplification source ports drop_reflection drops (replaces the default list "
		 "53 123 389 1900 11211 19 161 111 137 5353 3702 3283 5683 10001).",
	  .args = { .min_args = 1, .max_args = BST_XDP_MAX_REFL_PORTS, .pos = { { .kind = BST_T_STRING } } } },
	{ .name = "quic_check", .contexts = XC, .apply = ap_flag,
	  .doc = "On `http3` ports, drop datagrams that can not be QUIC: fixed bit clear, or a v1/v2 "
		 "Initial under 1200 bytes. Unknown versions pass (version negotiation). On by "
		 "default; inactive without an http3 listener.",
	  ONE({ .kind = BST_T_BOOL }) },
	{ .name = "syn_rate", .contexts = XC, .apply = ap_rate,
	  .doc = "Per-source rate of new TCP connections (SYN without ACK) to protected ports, as "
		 "`syn_rate 200/s burst=400`. The buckets are per CPU: the total is divided by the "
		 "online CPU count, so a source spread over several CPUs gets up to the total each.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_RATE } }, .opts = burst_opt, .nopts = 1 } },
	{ .name = "udp_rate", .contexts = XC, .apply = ap_rate,
	  .doc = "Per-source rate of UDP datagrams to protected (http3) ports, like syn_rate.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_RATE } }, .opts = burst_opt, .nopts = 1 } },
	{ .name = "pps_rate", .contexts = XC, .apply = ap_rate,
	  .doc = "Per-source rate of every packet to protected ports, like syn_rate.",
	  .args = { .min_args = 1, .max_args = 1, .pos = { { .kind = BST_T_RATE } }, .opts = burst_opt, .nopts = 1 } },
	{ .name = "auto_block", .contexts = XC, .apply = ap_auto_block,
	  .doc = "Off by default. `auto_block after=50 for=10s`: a source a rate limit drops `after` "
		 "times within a second is blocked in XDP for `for` (default 10s, at most 1h). Spoofed "
		 "packets can trigger it, so it only ever blocks that source key (an IPv6 prefix), "
		 "briefly; allow always wins.",
	  .args = { .min_args = 0, .max_args = 1, .pos = { { .kind = BST_T_STRING } }, .opts = auto_opts, .nopts = 2 } },
};
BST_DIRECTIVES(xdp_dirs);

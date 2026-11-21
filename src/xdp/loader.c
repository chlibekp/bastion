/* See loader.h. The object is embedded by tools/embed.mk as bst_embed_xdp_bastion[_end]. */
#include "xdp/loader.h"

#include "core/log.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

extern const unsigned char bst_embed_xdp_bastion[];
extern const unsigned char bst_embed_xdp_bastion_end[];

#define BPF_FS_MAGIC_ 0xcafe4a11
#define PIN_DEFAULT "/sys/fs/bpf/bastion"

static const char *const map_names[] = { "cfg",	   "stats",	 "allow4",     "allow6", "deny4",
					 "deny6", "dyn_block4", "dyn_block6", "rate" };
#define NMAPS (sizeof map_names / sizeof *map_names)

struct bst_xdp {
	struct bpf_object *obj;
	int prog_fd;
	size_t n;
	int link[BST_XDP_MAX_IFACES];
	char ifname[BST_XDP_MAX_IFACES][IF_NAMESIZE];
	const char *mode[BST_XDP_MAX_IFACES];
	char pin[200];
	bool pinned, keep;
	uint8_t gen; /* value of the list entries the last reconfigure wrote */
};

static char last_msg[256];
/* The verifier's own reason for a refused load: the last two lines of the program load log
 * libbpf prints (its later one-line hints, such as "try raising 'ulimit -l'", say little). */
static char verifier_msg[256];

static void keep_verifier_tail(const char *log)
{
	const char *end = strstr(log, "-- END PROG LOAD LOG --");
	const char *start = strstr(log, "-- BEGIN PROG LOAD LOG --");
	if (end == NULL || start == NULL || end < start)
		return;
	start = strchr(start, '\n');
	if (start == NULL || start >= end)
		return;
	start++;
	/* back over the trailing newline(s), then over two lines */
	const char *p = end;
	while (p > start && (p[-1] == '\n' || p[-1] == ' '))
		p--;
	const char *stop = p;
	for (int lines = 0; p > start; p--) {
		if (p[-1] == '\n' && ++lines == 2)
			break;
	}
	size_t k = 0;
	for (const char *q = p; q < stop && k + 3 < sizeof verifier_msg; q++) {
		if (*q == '\n') {
			verifier_msg[k++] = ';';
			verifier_msg[k++] = ' ';
		} else { /* it reaches the log: printable ASCII only */
			verifier_msg[k++] = (char)(*q >= 0x20 && *q < 0x7f ? *q : '?');
		}
	}
	verifier_msg[k] = '\0';
}

static int on_print(enum libbpf_print_level lvl, const char *fmt, va_list ap) __attribute__((format(printf, 2, 0)));
static int on_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl != LIBBPF_WARN)
		return 0;
	/* Formatted whole: the load log can be far longer than last_msg. */
	char *full = NULL;
	if (vasprintf(&full, fmt, ap) < 0)
		return 0;
	if (strstr(full, "-- END PROG LOAD LOG --") != NULL) {
		keep_verifier_tail(full);
	} else {
		snprintf(last_msg, sizeof last_msg, "%s", full);
		size_t n = strlen(last_msg);
		while (n > 0 && (last_msg[n - 1] == '\n' || last_msg[n - 1] == ' '))
			last_msg[--n] = '\0';
	}
	free(full);
	return 0;
}

static void fail(bst_err *e, const char *what, int err)
{
	if (last_msg[0] && verifier_msg[0])
		bst_err_set(e, "xdp: %s: %s (verifier: %s; %s)", what, strerror(err), verifier_msg,
			    last_msg);
	else if (last_msg[0] || verifier_msg[0])
		bst_err_set(e, "xdp: %s: %s (%s)", what, strerror(err),
			    last_msg[0] ? last_msg : verifier_msg);
	else
		bst_err_set(e, "xdp: %s: %s", what, strerror(err));
}

static bool is_bpffs(const char *path)
{
	struct statfs s;
	return statfs(path, &s) == 0 && (unsigned long)s.f_type == BPF_FS_MAGIC_;
}

/* The pin directory, created inside a bpffs mount. False when there is none to use. */
static bool pin_dir(const char *path)
{
	if (is_bpffs(path))
		return true;
	char parent[200];
	snprintf(parent, sizeof parent, "%s", path);
	char *slash = strrchr(parent, '/');
	if (slash == NULL || slash == parent)
		return false;
	*slash = '\0';
	if (!is_bpffs(parent))
		return false;
	return mkdir(path, 0700) == 0 || errno == EEXIST ? is_bpffs(path) : false;
}

static void path_of(char *out, size_t cap, const char *dir, const char *pfx, const char *name)
{
	snprintf(out, cap, "%s/%s%s", dir, pfx, name);
}

int bst_xdp_adopt_pinned(const char *pin_path)
{
	if (pin_path == NULL)
		pin_path = PIN_DEFAULT;
	if (!is_bpffs(pin_path))
		return 0;
	char p[300];
	int n = 0;
	for (unsigned i = 1; i < 4096; i++) {
		char name[IF_NAMESIZE];
		if (if_indextoname(i, name) == NULL)
			continue;
		path_of(p, sizeof p, pin_path, "link_", name);
		n += access(p, F_OK) == 0;
	}
	return n;
}

/* ---- maps ---- */

int bst_xdp_map_fd(const bst_xdp *x, const char *name)
{
	struct bpf_map *m = bpf_object__find_map_by_name(x->obj, name);
	return m == NULL ? -1 : bpf_map__fd(m);
}

static int put_cidr(int fd4, int fd6, const bst_cidr *c, uint8_t gen)
{
	bst_ip ip = bst_ip_canon(&c->ip);
	if (ip.family == BST_IP_V4) {
		struct bst_xdp_lpm4 k = { .prefixlen = c->ip.family == BST_IP_V4 ? c->prefix
										   : (c->prefix > 96 ? c->prefix - 96u : 0) };
		memcpy(k.addr, ip.b, 4);
		return bpf_map_update_elem(fd4, &k, &gen, BPF_ANY);
	}
	struct bst_xdp_lpm6 k = { .prefixlen = c->prefix };
	memcpy(k.addr, ip.b, 16);
	return bpf_map_update_elem(fd6, &k, &gen, BPF_ANY);
}

/* Deletes the entries a previous generation wrote. */
static void sweep(int fd, size_t ksize, uint8_t gen)
{
	uint8_t key[sizeof(struct bst_xdp_lpm6)], next[sizeof(struct bst_xdp_lpm6)], stale[64][sizeof(struct bst_xdp_lpm6)];
	for (;;) {
		size_t ns = 0;
		void *cur = NULL;
		while (ns < 64 && bpf_map_get_next_key(fd, cur, next) == 0) {
			memcpy(key, next, ksize);
			cur = key;
			uint8_t v = 0;
			if (bpf_map_lookup_elem(fd, key, &v) == 0 && v != gen)
				memcpy(stale[ns++], key, ksize);
		}
		for (size_t i = 0; i < ns; i++)
			(void)bpf_map_delete_elem(fd, stale[i]);
		if (ns < 64)
			return;
	}
}

static int fill_lists(bst_xdp *x, const bst_cidr *v, size_t n, const char *m4, const char *m6, bst_err *e)
{
	int fd4 = bst_xdp_map_fd(x, m4), fd6 = bst_xdp_map_fd(x, m6);
	for (size_t i = 0; i < n; i++)
		if (put_cidr(fd4, fd6, &v[i], x->gen) != 0) {
			fail(e, m4[0] == 'a' ? "allow list" : "deny list", errno);
			return -1;
		}
	sweep(fd4, sizeof(struct bst_xdp_lpm4), x->gen);
	sweep(fd6, sizeof(struct bst_xdp_lpm6), x->gen);
	return 0;
}

/* The generation value found in the list maps (all entries share it), or 0 when they are empty. */
static uint8_t pinned_gen(bst_xdp *x)
{
	static const struct { const char *name; size_t ksize; } lists[] = {
		{ "allow4", sizeof(struct bst_xdp_lpm4) }, { "deny4", sizeof(struct bst_xdp_lpm4) },
		{ "allow6", sizeof(struct bst_xdp_lpm6) }, { "deny6", sizeof(struct bst_xdp_lpm6) },
	};
	uint8_t key[sizeof(struct bst_xdp_lpm6)];
	for (size_t i = 0; i < sizeof lists / sizeof lists[0]; i++) {
		int fd = bst_xdp_map_fd(x, lists[i].name);
		uint8_t v = 0;
		if (fd >= 0 && bpf_map_get_next_key(fd, NULL, key) == 0 &&
		    bpf_map_lookup_elem(fd, key, &v) == 0 && v != 0)
			return v;
	}
	return 0;
}

int bst_xdp_reconfigure(bst_xdp *x, const bst_cfg_xdp *cfg, bst_err *e)
{
	struct bst_xdp_config c;
	memset(&c, 0, sizeof c);
	c.flags = cfg->flags;
	c.ntcp = (uint16_t)cfg->ntcp;
	memcpy(c.tcp_ports, cfg->tcp_ports, sizeof c.tcp_ports);
	c.nudp = (uint16_t)cfg->nudp;
	memcpy(c.udp_ports, cfg->udp_ports, sizeof c.udp_ports);
	/* every protected UDP port is an `http3` one */
	c.nquic = (uint16_t)cfg->nudp;
	memcpy(c.quic_ports, cfg->udp_ports, sizeof c.quic_ports);
	c.nrefl = (uint16_t)cfg->nrefl;
	memcpy(c.refl_ports, cfg->refl_ports, sizeof c.refl_ports);
	c.v6_prefix = (uint16_t)(cfg->ipv6_prefix ? cfg->ipv6_prefix : 64);
	bst_xdp_v6_mask(c.v6_prefix, c.v6_mask);
	long on = sysconf(_SC_NPROCESSORS_ONLN);
	unsigned ncpu = on > 0 ? (unsigned)on : 1;
	c.syn_rate = bst_xdp_per_cpu(cfg->syn_rate, ncpu);
	c.syn_burst = bst_xdp_per_cpu(cfg->syn_burst, ncpu);
	c.udp_rate = bst_xdp_per_cpu(cfg->udp_rate, ncpu);
	c.udp_burst = bst_xdp_per_cpu(cfg->udp_burst, ncpu);
	c.pps_rate = bst_xdp_per_cpu(cfg->pps_rate, ncpu);
	c.pps_burst = bst_xdp_per_cpu(cfg->pps_burst, ncpu);
	c.auto_after = cfg->auto_after;
	c.auto_ns = cfg->auto_ns;
	uint32_t zero = 0;
	last_msg[0] = '\0';
	verifier_msg[0] = '\0';
	if (bpf_map_update_elem(bst_xdp_map_fd(x, "cfg"), &zero, &c, BPF_ANY) != 0) {
		fail(e, "config map", errno);
		return -1;
	}
	x->gen = (uint8_t)(x->gen == 255 ? 1 : x->gen + 1);
	if (fill_lists(x, cfg->allow, cfg->nallow, "allow4", "allow6", e) != 0 ||
	    fill_lists(x, cfg->deny, cfg->ndeny, "deny4", "deny6", e) != 0)
		return -1;
	return 0;
}

/* ---- attach ---- */

static int try_mode(int prog, int ifindex, uint32_t flags)
{
	LIBBPF_OPTS(bpf_link_create_opts, o, .flags = flags);
	return bpf_link_create(prog, ifindex, BPF_XDP, &o);
}

/* Attaches to one interface (or adopts its pinned link). 0, or -1 with err set. */
static int attach_one(bst_xdp *x, const bst_cfg_xdp *cfg, const char *name, bst_err *e)
{
	size_t i = x->n;
	snprintf(x->ifname[i], IF_NAMESIZE, "%s", name);
	unsigned idx = if_nametoindex(name);
	if (idx == 0) {
		bst_err_set(e, "xdp: interface %s: %s", name, strerror(errno));
		return -1;
	}
	char lp[300];
	path_of(lp, sizeof lp, x->pin, "link_", name);
	if (x->pinned && access(lp, F_OK) == 0) {
		int fd = bpf_obj_get(lp);
		if (fd >= 0 && bpf_link_update(fd, x->prog_fd, NULL) == 0) {
			x->link[i] = fd;
			x->mode[i] = "adopted";
			x->n++;
			return 0;
		}
		/* a stale pin (its interface was removed and re-created): replace it */
		if (fd >= 0)
			close(fd);
		(void)unlink(lp);
	}
	int fd = -1;
	int err = 0;
	const char *got = NULL;
	if (cfg->mode == BST_XDP_AUTO || cfg->mode == BST_XDP_NATIVE) {
		fd = try_mode(x->prog_fd, (int)idx, XDP_FLAGS_DRV_MODE);
		got = "native";
	} else if (cfg->mode == BST_XDP_HW) {
		fd = try_mode(x->prog_fd, (int)idx, XDP_FLAGS_HW_MODE);
		got = "hw";
	}
	if (fd < 0 && cfg->mode != BST_XDP_GENERIC) {
		err = errno;
		if (cfg->require) {
			bst_err_set(e, "xdp: %s: %s mode refused (%s) and `require` is set", name, got, strerror(err));
			return -1;
		}
		if (cfg->mode != BST_XDP_AUTO)
			bst_log(BST_LOG_WARN, "xdp: %s: %s mode refused (%s): using generic", name, got, strerror(err));
	}
	if (fd < 0) {
		fd = try_mode(x->prog_fd, (int)idx, XDP_FLAGS_SKB_MODE);
		got = "generic";
		if (fd < 0) {
			fail(e, name, errno);
			return -1;
		}
	}
	if (x->pinned && bpf_obj_pin(fd, lp) != 0)
		bst_log(BST_LOG_WARN, "xdp: %s: cannot pin the link at %s (%s): it ends with this process",
			name, lp, strerror(errno));
	x->link[i] = fd;
	x->mode[i] = got;
	x->n++;
	return 0;
}

static void unpin_maps(const char *dir)
{
	char p[300];
	for (size_t i = 0; i < NMAPS; i++) {
		path_of(p, sizeof p, dir, "", map_names[i]);
		(void)unlink(p);
	}
}

static int open_load(bst_xdp *x, const bst_cfg_xdp *cfg, bst_err *e)
{
	size_t len = (size_t)(bst_embed_xdp_bastion_end - bst_embed_xdp_bastion);
	LIBBPF_OPTS(bpf_object_open_opts, oo, .object_name = "bst_xdp");
	x->obj = bpf_object__open_mem(bst_embed_xdp_bastion, len, &oo);
	if (x->obj == NULL) {
		fail(e, "open", errno);
		return -1;
	}
	unsigned dyn = cfg->dyn_size >= 1024 ? cfg->dyn_size : 1024;
	struct bpf_map *m;
	bpf_object__for_each_map(m, x->obj) {
		const char *n = bpf_map__name(m);
		if (strcmp(n, "dyn_block4") == 0 || strcmp(n, "dyn_block6") == 0)
			(void)bpf_map__set_max_entries(m, dyn);
		if (x->pinned) {
			char p[300];
			path_of(p, sizeof p, x->pin, "", n);
			(void)bpf_map__set_pin_path(m, p); /* reused when pinned and compatible, else pinned */
		}
	}
	if (bpf_object__load(x->obj) != 0) {
		fail(e, "load", errno);
		bpf_object__close(x->obj);
		x->obj = NULL;
		return -1;
	}
	struct bpf_program *p = bpf_object__find_program_by_name(x->obj, "bst_xdp");
	if (p == NULL) {
		bst_err_set(e, "xdp: embedded object has no program");
		return -1;
	}
	x->prog_fd = bpf_program__fd(p);
	return 0;
}

bst_xdp *bst_xdp_load(const bst_cfg_xdp *cfg, bst_err *e)
{
	libbpf_set_print(on_print);
	last_msg[0] = '\0';
	verifier_msg[0] = '\0';
	if (cfg->nifaces == 0) {
		bst_err_set(e, "xdp: no interface");
		return NULL;
	}
	bst_xdp *x = calloc(1, sizeof *x);
	if (x == NULL) {
		bst_err_set(e, "xdp: out of memory");
		return NULL;
	}
	snprintf(x->pin, sizeof x->pin, "%s", cfg->pin_path ? cfg->pin_path : PIN_DEFAULT);
	x->keep = cfg->on_exit_keep;
	x->pinned = pin_dir(x->pin);
	if (!x->pinned)
		bst_log(BST_LOG_WARN, "xdp: %s is not on a bpffs mount: nothing is pinned, so the filter "
				      "ends with this process whatever on_exit says", x->pin);
	char cp[300];
	path_of(cp, sizeof cp, x->pin, "", "cfg");
	bool had_pins = x->pinned && access(cp, F_OK) == 0;
	if (open_load(x, cfg, e) != 0) {
		if (!had_pins || x->obj != NULL) {
			free(x);
			return NULL;
		}
		/* pinned maps of an incompatible older layout: start them afresh */
		bst_log(BST_LOG_WARN, "xdp: pinned maps under %s do not fit this build (%s): replacing them",
			x->pin, e->msg);
		unpin_maps(x->pin);
		if (open_load(x, cfg, e) != 0) {
			free(x);
			return NULL;
		}
	}
	/* Reused pinned lists (a reload or a restart) carry the previous process's generation: start
	 * from it, so this fill writes a different value and the sweep removes what was dropped. */
	x->gen = pinned_gen(x);
	if (bst_xdp_reconfigure(x, cfg, e) != 0)
		goto fail;
	for (size_t i = 0; i < cfg->nifaces; i++)
		if (attach_one(x, cfg, cfg->ifaces[i], e) != 0)
			goto fail;
	return x;
fail:
	x->keep = false;
	bst_xdp_detach(x);
	return NULL;
}

const char *bst_xdp_mode_of(const bst_xdp *x, size_t i)
{
	return x != NULL && i < x->n ? x->mode[i] : "none";
}

void bst_xdp_hand_over(bst_xdp *x)
{
	if (x != NULL && x->pinned)
		x->keep = true;
}

int bst_xdp_take_back(bst_xdp *x)
{
	if (x == NULL)
		return 0;
	int rc = 0;
	for (size_t i = 0; i < x->n; i++)
		if (bpf_link_update(x->link[i], x->prog_fd, NULL) != 0) {
			bst_log(BST_LOG_ERROR, "xdp: %s: cannot take the filter back: %s", x->ifname[i],
				strerror(errno));
			rc = -1;
		}
	return rc;
}

void bst_xdp_detach(bst_xdp *x)
{
	if (x == NULL)
		return;
	bool keep = x->keep && x->pinned;
	char p[300];
	for (size_t i = 0; i < x->n; i++) {
		if (!keep && x->pinned) {
			path_of(p, sizeof p, x->pin, "link_", x->ifname[i]);
			(void)unlink(p);
		}
		/* Children forked after the load hold copies of this fd (they never use it: seccomp has
		 * no bpf()), so closing ours is not the last reference: detach explicitly. */
		if (!keep)
			(void)bpf_link_detach(x->link[i]);
		close(x->link[i]);
	}
	if (!keep && x->pinned)
		unpin_maps(x->pin);
	if (x->obj != NULL)
		bpf_object__close(x->obj);
	free(x);
}

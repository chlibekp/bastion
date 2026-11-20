/* See doctor.h. */
#include "ops/doctor.h"

#include "config/compile.h"
#include "config/parser.h"
#include "config/template.h"
#include "core/arena.h"
#include "ops/numa.h"

#include <bpf/libbpf.h>
#include <errno.h>
/* liburing's inline helpers do not build under -Wconversion -Wsign-conversion -Wshadow. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <liburing.h>
#pragma GCC diagnostic pop
#include <linux/landlock.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

typedef enum { OK, WARN, MISSING, INFO } verdict;
static const char *const vname[] = { "ok", "warn", "missing", "info" };

static void row(const char *name, verdict v, const char *recommend, const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));
static void row(const char *name, verdict v, const char *recommend, const char *fmt, ...)
{
	char val[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(val, sizeof val, fmt, ap);
	va_end(ap);
	printf("%-22s %-8s %-28s %s\n", name, vname[v], val, recommend);
}

/* The first line of a /proc or /sys file, trimmed; NULL when unreadable. */
static const char *read_line(const char *path, char *buf, size_t cap)
{
	FILE *f = fopen(path, "re");
	if (f == NULL)
		return NULL;
	const char *r = fgets(buf, (int)cap, f);
	fclose(f);
	if (r == NULL)
		return NULL;
	buf[strcspn(buf, "\n")] = '\0';
	return buf;
}

static long read_long(const char *path)
{
	char b[64];
	return read_line(path, b, sizeof b) != NULL ? strtol(b, NULL, 10) : -1;
}

static bool word_in(const char *path, const char *w)
{
	char b[512];
	if (read_line(path, b, sizeof b) == NULL)
		return false;
	for (char *t = strtok(b, " \t"); t != NULL; t = strtok(NULL, " \t"))
		if (strcmp(t, w) == 0)
			return true;
	return false;
}

typedef struct facts {
	int kmaj, kmin;
	bool uring, napi, ktls, bpf, landlock, seccomp;
	int landlock_abi;
} facts;

static void kernel(facts *f)
{
	struct utsname u;
	if (uname(&u) != 0) {
		row("kernel", WARN, ">= 6.1", "unknown");
		return;
	}
	sscanf(u.release, "%d.%d", &f->kmaj, &f->kmin);
	bool new_enough = f->kmaj > 6 || (f->kmaj == 6 && f->kmin >= 1);
	row("kernel", new_enough ? OK : WARN, ">= 6.1 (6.9 for NAPI busy poll)", "%s", u.release);
}

static void io_uring(facts *f)
{
	struct io_uring ring;
	int rc = io_uring_queue_init(4, &ring, 0);
	f->uring = rc == 0;
	long disabled = read_long("/proc/sys/kernel/io_uring_disabled");
	if (rc == 0) {
		struct io_uring_napi n = { .busy_poll_to = 0 };
		f->napi = io_uring_register_napi(&ring, &n) == 0; /* registered on a ring freed next */
		io_uring_queue_exit(&ring);
	}
	row("io_uring", f->uring ? OK : MISSING, "available (backend auto uses it)", "%s%s",
	    f->uring ? "available" : strerror(-rc),
	    disabled > 0 ? " (kernel.io_uring_disabled)" : "");
	row("io_uring NAPI", f->napi ? OK : INFO, "for uring_napi", "%s", f->napi ? "available" : "not available");
}

static void ktls(facts *f)
{
	f->ktls = word_in("/proc/sys/net/ipv4/tcp_available_ulp", "tls") || access("/sys/module/tls", F_OK) == 0;
	row("kTLS", f->ktls ? OK : WARN, "tls module loaded (ktls tx)", "%s",
	    f->ktls ? "available" : "tls module not loaded");
}

static void bpf(facts *f)
{
	f->bpf = libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_XDP, NULL) == 1;
	long jit = read_long("/proc/sys/net/core/bpf_jit_enable");
	row("BPF (XDP)", f->bpf ? OK : WARN, "loadable, JIT on (xdp {})", "%s%s",
	    f->bpf ? "loadable" : "not loadable here", jit == 0 ? ", JIT off" : "");
}

static void sandbox(facts *f)
{
	long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	f->landlock = abi > 0;
	f->landlock_abi = (int)abi;
	row("Landlock", f->landlock ? OK : WARN, "available (sandbox landlock)", "%s",
	    f->landlock ? "available" : "not available");
	char b[256];
	FILE *s = fopen("/proc/self/status", "re");
	while (s != NULL && fgets(b, sizeof b, s) != NULL)
		if (strncmp(b, "Seccomp:", 8) == 0)
			f->seccomp = true;
	if (s != NULL)
		fclose(s);
	row("seccomp", f->seccomp ? OK : MISSING, "available (sandbox seccomp)", "%s",
	    f->seccomp ? "available" : "not available");
}

static void net(void)
{
	char cc[64] = "?";
	bool bbr = word_in("/proc/sys/net/ipv4/tcp_available_congestion_control", "bbr");
	read_line("/proc/sys/net/ipv4/tcp_congestion_control", cc, sizeof cc);
	row("BBR", bbr ? OK : INFO, "available (tcp_profile congestion bbr)", "%s (current %s)",
	    bbr ? "available" : "not available", cc);
	long bp = read_long("/proc/sys/net/core/busy_poll"), br = read_long("/proc/sys/net/core/busy_read");
	if (bp < 0)
		row("busy_poll", INFO, "0, or 50 for latency-bound hosts", "not exposed here");
	else
		row("busy_poll", INFO, "0, or 50 for latency-bound hosts", "busy_poll=%ld busy_read=%ld", bp, br);
	long sc = read_long("/proc/sys/net/ipv4/tcp_syncookies");
	row("tcp_syncookies", sc == 1 ? OK : WARN, "1", "%ld", sc);
	long so = read_long("/proc/sys/net/core/somaxconn");
	row("somaxconn", so >= 4096 ? OK : WARN, ">= 4096 (backlog is capped by it)", "%ld", so);
	long sb = read_long("/proc/sys/net/ipv4/tcp_max_syn_backlog");
	row("tcp_max_syn_backlog", sb >= 4096 ? OK : WARN, ">= 4096", "%ld", sb);
}

static void limits(void)
{
	struct rlimit r;
	getrlimit(RLIMIT_NOFILE, &r);
	row("fd limit (nofile)", r.rlim_cur >= 65536 ? OK : WARN, ">= 65536 (or worker_rlimit_nofile)",
	    "soft %llu, hard %llu", (unsigned long long)r.rlim_cur, (unsigned long long)r.rlim_max);
	long fm = read_long("/proc/sys/fs/file-max"), no = read_long("/proc/sys/fs/nr_open");
	row("fs.file-max", fm < 0 || fm >= 1048576 ? OK : WARN, ">= 1048576", "%ld (nr_open %ld)", fm, no);
	getrlimit(RLIMIT_MEMLOCK, &r);
	row("memlock", INFO, "unlimited for XDP on old kernels", "%s",
	    r.rlim_cur == RLIM_INFINITY ? "unlimited" : "limited");
}

static void cpus(void)
{
	int c[BST_CPU_LIST_MAX];
	size_t n = bst_cpus_allowed(c, BST_CPU_LIST_MAX);
	long on = sysconf(_SC_NPROCESSORS_ONLN);
	row("CPUs", INFO, "workers auto uses the allowed ones", "%zu allowed of %ld online", n, on);
	row("NUMA nodes", INFO, "numa auto", "%d", bst_numa_nodes());
	char m[32];
	const char *thp = bst_thp_mode(m, sizeof m);
	row("transparent hugepages", thp != NULL && strcmp(thp, "never") != 0 ? OK : INFO,
	    "always or madvise (huge_pages)", "%s", thp != NULL ? thp : "unknown");
}

/* Each `require` of the config against what the host has: the number that would fail. */
static int requires(const bst_config *cfg, const facts *f)
{
	int bad = 0;
	const bst_cfg_global *g = &cfg->global;
	if (g->io.napi_require && !f->napi) {
		printf("require: uring_napi on require would fail: NAPI busy polling is not available\n");
		bad++;
	}
	bool kt = g->tls_default.ktls_require;
	for (size_t i = 0; i < g->ntls_profiles; i++)
		kt |= g->tls_profiles[i]->ktls_require;
	if (kt && !f->ktls) {
		printf("require: ktls ... require would fail: the kernel tls module is not loaded\n");
		bad++;
	}
	if (g->sandbox.landlock && g->sandbox.landlock_require && !f->landlock) {
		printf("require: landlock require would fail: the kernel has no Landlock\n");
		bad++;
	}
	if (g->sandbox.seccomp != BST_SECCOMP_OFF && g->sandbox.seccomp_require && !f->seccomp) {
		printf("require: seccomp require would fail: the kernel has no seccomp\n");
		bad++;
	}
	if (bad == 0)
		printf("require: every require of the configuration can be met here\n");
	return bad;
}

int bst_doctor_main(int argc, char **argv)
{
	const char *conf = NULL;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
			conf = argv[++i];
		} else {
			fprintf(stderr, "usage: bastion doctor [-c file]\n");
			return 2;
		}
	}
	bst_config *cfg = NULL;
	bst_arena *arena = NULL;
	if (conf != NULL) {
		bst_err e = { .msg = "" };
		arena = bst_arena_new((size_t)64 << 10);
		bst_cfg_opts popts = { .known_var = bst_tpl_var_known };
		bst_ast *ast = arena != NULL ? bst_cfg_parse_file_opts(conf, &popts, arena, &e) : NULL;
		cfg = ast != NULL ? bst_cfg_compile(ast, &e) : NULL;
		if (cfg == NULL) {
			fprintf(stderr, "%s: %s\n", conf, e.msg);
			bst_arena_free(arena);
			return 2;
		}
	}
	facts f = { 0 };
	printf("%-22s %-8s %-28s %s\n", "check", "status", "value", "recommended");
	kernel(&f);
	io_uring(&f);
	ktls(&f);
	bpf(&f);
	sandbox(&f);
	net();
	limits();
	cpus();
	int bad = cfg != NULL ? requires(cfg, &f) : 0;
	printf("doctor only reads: no setting was changed\n");
	bst_config_free(cfg);
	bst_arena_free(arena);
	return bad > 0 ? 1 : 0;
}

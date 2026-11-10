/* See sandbox.h. */
#include "proc/sandbox_priv.h"

#include "core/log.h"
#include "io/aio.h"
#include "io/uring_priv.h" /* the exception architecture section 3 allows */
#include "proc/seccomp.h"
#include "proc/test_hooks.h"

#include <errno.h>
#include <linux/capability.h>
#include <linux/seccomp.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define BST_ASAN 1
#include <sanitizer/common_interface_defs.h>
#endif
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1ul
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif
#define FILTER_MAX 512u /* instructions; bst_seccomp_build says if the table outgrows it */

/* ---- every thread ---- */

static bst_loop *pool_loop;

void bst_sandbox_set_loop(bst_loop *l)
{
	pool_loop = l;
}

int bst_sandbox_each_thread(void (*fn)(void *), void *arg)
{
	fn(arg);
	return pool_loop != NULL ? bst_aio_each_thread(pool_loop, fn, arg) : 0;
}

/* ---- capabilities ---- */

static int capget_self(struct __user_cap_data_struct d[2])
{
	struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
	return (int)syscall(SYS_capget, &h, d);
}

static int capset_self(const struct __user_cap_data_struct d[2])
{
	struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
	return (int)syscall(SYS_capset, &h, d);
}

typedef struct caps_job {
	atomic_int failed;     /* an errno */
	atomic_bool bounding_kept;
} caps_job;

static void keep_caps_thread(void *arg)
{
	caps_job *j = arg;
	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0)
		atomic_store(&j->failed, errno);
}

int bst_sandbox_keep_caps(bst_err *err)
{
	caps_job j = { 0 };
	int rc = bst_sandbox_each_thread(keep_caps_thread, &j);
	if (rc != 0 || atomic_load(&j.failed) != 0) {
		bst_err_set(err, "PR_SET_KEEPCAPS: %s", strerror(rc != 0 ? -rc : atomic_load(&j.failed)));
		return -1;
	}
	return 0;
}

static void drop_bounding(caps_job *j)
{
	for (int cap = 0; cap < 64; cap++)
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) {
			if (errno != EINVAL) /* EINVAL: past the last capability this kernel has */
				atomic_store(&j->failed, errno);
			return;
		}
}

/* Dropping the bounding set takes CAP_SETPCAP, which setuid took out of the effective set: it
 * stays in the permitted one under PR_SET_KEEPCAPS, and comes back for this. */
static void drop_caps_thread(void *arg)
{
	caps_job *j = arg;
	struct __user_cap_data_struct d[2];
	if (capget_self(d) != 0) {
		atomic_store(&j->failed, errno);
		return;
	}
	bool setpcap = (d[CAP_TO_INDEX(CAP_SETPCAP)].permitted & CAP_TO_MASK(CAP_SETPCAP)) != 0;
	if (setpcap) {
		d[CAP_TO_INDEX(CAP_SETPCAP)].effective |= CAP_TO_MASK(CAP_SETPCAP);
		if (capset_self(d) != 0) {
			atomic_store(&j->failed, errno);
			return;
		}
		drop_bounding(j);
	} else {
		atomic_store(&j->bounding_kept, true);
	}
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 && errno != EINVAL)
		atomic_store(&j->failed, errno);
	(void)prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
	memset(d, 0, sizeof d);
	if (capset_self(d) != 0)
		atomic_store(&j->failed, errno);
}

int bst_sandbox_drop_caps(const bst_cfg_sandbox *cfg, bst_err *err)
{
	caps_job j = { 0 };
	int rc = bst_sandbox_each_thread(drop_caps_thread, &j);
	if (rc != 0 || atomic_load(&j.failed) != 0) {
		bst_err_set(err, "dropping capabilities: %s",
			    strerror(rc != 0 ? -rc : atomic_load(&j.failed)));
		return -1;
	}
	if (atomic_load(&j.bounding_kept)) {
		if (cfg->drop_caps_require) {
			bst_err_set(err, "drop_capabilities require: the bounding set needs CAP_SETPCAP");
			return -1;
		}
		bst_log(BST_LOG_WARN, "sandbox: the capability bounding set is kept: it takes "
			"CAP_SETPCAP to empty it, and no_new_privs makes it inert");
	}
	return 0;
}

/* ---- steps 4 to 6 ---- */

typedef struct nnp_job {
	atomic_int failed;
} nnp_job;

static void nnp_thread(void *arg)
{
	nnp_job *j = arg;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		atomic_store(&j->failed, errno);
}

/* Step 4. Dumpable and the limit belong to the process, no_new_privs to each thread, and Landlock
 * asks for it on the thread that restricts itself. */
static int harden(bst_err *e)
{
	nnp_job j = { 0 };
	int rc = bst_sandbox_each_thread(nnp_thread, &j);
	if (rc != 0 || atomic_load(&j.failed) != 0) {
		bst_err_set(e, "PR_SET_NO_NEW_PRIVS: %s",
			    strerror(rc != 0 ? -rc : atomic_load(&j.failed)));
		return -1;
	}
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
		bst_err_set(e, "PR_SET_DUMPABLE: %s", strerror(errno));
		return -1;
	}
	struct rlimit none = { 0, 0 };
	if (setrlimit(RLIMIT_CORE, &none) != 0) {
		bst_err_set(e, "RLIMIT_CORE: %s", strerror(errno));
		return -1;
	}
	return 0;
}

/* Step 5. *state is what the summary line says. */
static int landlock_step(const bst_cfg_sandbox *c, const bst_sandbox_paths *p, char *state,
			 size_t cap, bst_err *e)
{
	if (!c->landlock) {
		snprintf(state, cap, "off");
		return 0;
	}
	int abi = 0, rc = bst_landlock_apply(p, &abi, e);
	if (rc < 0)
		return -1;
	if (rc == 0) {
		snprintf(state, cap, "abi%d", abi);
		return 0;
	}
	if (c->landlock_require) {
		bst_err_set(e, "landlock require: the kernel has no Landlock");
		return -1;
	}
	bst_log(BST_LOG_WARN, "sandbox: landlock unavailable: file access is limited by "
		"permissions and seccomp only");
	snprintf(state, cap, "unavailable");
	return 0;
}

#if defined(__x86_64__)
#define THIS_ARCH BST_ARCH_X86_64
#elif defined(__aarch64__)
#define THIS_ARCH BST_ARCH_AARCH64
#else
#error "sandbox: add this architecture to seccomp_tables.c"
#endif

/* Step 6, the last one: it forbids most of what the others called. */
static int seccomp_step(const bst_cfg_sandbox *c, bst_sandbox_role role, const char **state,
			bst_err *e)
{
	static const char *const names[] = { [BST_SECCOMP_OFF] = "off", [BST_SECCOMP_ON] = "on",
					     [BST_SECCOMP_LOG] = "log" };
	*state = names[c->seccomp];
	if (c->seccomp == BST_SECCOMP_OFF)
		return 0;
	static struct sock_filter ins[FILTER_MAX];
	bst_seccomp_opts o = { .arch = THIS_ARCH, .role = role, .mode = c->seccomp,
			       .self_pid = (uint32_t)getpid() };
	long n = bst_seccomp_build(&o, ins, FILTER_MAX);
	if (n < 0) {
		bst_err_set(e, "seccomp: building the filter: %s", strerror((int)-n));
		return -1;
	}
	struct sock_fprog prog = { .len = (unsigned short)n, .filter = ins };
	long rc = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
	int err = errno;
#ifdef BST_TEST
	int inj = bst_test_sandbox_fail("tsync");
	if (inj != 0)
		rc = inj; /* the id of a thread that could not follow */
	inj = bst_test_sandbox_fail("seccomp");
	if (inj != 0) {
		rc = -1;
		err = inj;
	}
#endif
	if (rc > 0) { /* with TSYNC: a thread that could not follow, and is free of the filter */
		bst_err_set(e, "seccomp: TSYNC failed on thread %ld", rc);
		return -1;
	}
	if (rc == 0)
		return 0;
	if (err != ENOSYS || c->seccomp_require) {
		bst_err_set(e, "seccomp: %s", strerror(err));
		return -1;
	}
	bst_log(BST_LOG_WARN, "sandbox: seccomp unavailable: the kernel has no filter support");
	*state = "unavailable";
	return 0;
}

int bst_sandbox_apply(const bst_cfg_sandbox *cfg, bst_sandbox_role role,
		      const bst_sandbox_paths *paths, bst_err *err)
{
	char landlock[16];
	const char *seccomp;
	if (harden(err) != 0 || landlock_step(cfg, paths, landlock, sizeof landlock, err) != 0 ||
	    seccomp_step(cfg, role, &seccomp, err) != 0)
		return -1;
	if (cfg->seccomp == BST_SECCOMP_LOG)
		bst_log(BST_LOG_WARN, "sandbox: seccomp log: forbidden syscalls run, and only the "
			"kernel's audit log says so");
	bst_log(BST_LOG_INFO, "sandbox: seccomp=%s landlock=%s namespaces=%s capabilities=%s", seccomp,
		landlock, bst_ns_active() ? "on" : "off", cfg->drop_caps ? "dropped" : "kept");
	return 0;
}

/* ---- sanitizer builds ---- */

#ifdef BST_ASAN
static bool sanitizer_sandboxed;

/* LSan calls this before a leak check. Its docs ask for a constant, but all it does is read the
 * answer at that moment: master answers 0 for life, and a child 1 from its first step on, which
 * is what detect_leaks=0 would say if a process could change it after start. */
int __lsan_is_turned_off(void);
int __lsan_is_turned_off(void)
{
	return sanitizer_sandboxed;
}

/* The report file is opened here, while a child still may, and held for the report. Every
 * child of a PID namespace has pid 1, so a file name with the pid in it would be reused and
 * truncated: the tag and the clock make it unique. */
void bst_sandbox_sanitizer_prepare(const char *tag)
{
	sanitizer_sandboxed = true;
	const char *o = getenv("ASAN_OPTIONS");
	const char *p = o != NULL ? strstr(o, "log_path=") : NULL;
	if (p != NULL) {
		p += strlen("log_path=");
		size_t n = strcspn(p, ":");
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		char path[512], who[32];
		snprintf(who, sizeof who, "%s", tag);
		for (char *c = who; *c != '\0'; c++)
			if (*c == '/')
				*c = '-';
		snprintf(path, sizeof path, "%.*s.%s.%lld%09ld", (int)n, p, who,
			 (long long)ts.tv_sec, ts.tv_nsec);
		__sanitizer_set_report_path(path);
		(void)__sanitizer_get_report_path(); /* opens it */
	}
	__sanitizer_sandbox_on_notify(NULL); /* caches /proc/self/maps */
}
#else
void bst_sandbox_sanitizer_prepare(const char *tag)
{
	(void)tag;
}
#endif

/* ---- io_uring ---- */

/* The list: every opcode of the backend this kernel has. Split out for the unit test, which
 * hands it a probe with holes. How many entries res got, or -ENOSPC. */
int bst_uring_restrictions_(const struct io_uring_probe *pr, struct io_uring_restriction *res,
			    unsigned cap)
{
	unsigned n = 0;
	if (cap < bst_uring_nopcodes_ + bst_uring_nregister_ + 1)
		return -ENOSPC;
	memset(res, 0, cap * sizeof *res);
	for (unsigned i = 0; i < bst_uring_nopcodes_; i++)
		if (io_uring_opcode_supported(pr, bst_uring_opcodes_[i])) {
			res[n].opcode = IORING_RESTRICTION_SQE_OP;
			res[n++].sqe_op = bst_uring_opcodes_[i];
		}
	res[n].opcode = IORING_RESTRICTION_SQE_FLAGS_ALLOWED;
	res[n++].sqe_flags = BST_URING_SQE_FLAGS;
	for (unsigned i = 0; i < bst_uring_nregister_; i++) {
		res[n].opcode = IORING_RESTRICTION_REGISTER_OP;
		res[n++].register_op = bst_uring_register_ops_[i];
	}
	return (int)n;
}

void bst_sandbox_restrict_rings(void)
{
	bst_uring_pre_enable_ = bst_uring_restrict;
}

int bst_uring_restrict(struct io_uring *ring)
{
	struct io_uring_probe *pr = io_uring_get_probe_ring(ring);
	if (pr == NULL)
		return -EOPNOTSUPP;
	struct io_uring_restriction res[64];
	int n = bst_uring_restrictions_(pr, res, sizeof res / sizeof res[0]);
	io_uring_free_probe(pr);
	if (n < 0)
		return n;
	return io_uring_register_restrictions(ring, res, (unsigned)n);
}

/* Landlock (architecture section 8): read-only on serving roots, read-write on cache and temp
 * directories, nothing else. See sandbox.h.
 *
 * The rights are those of the best ABI the kernel has: ABI 2 on the 6.1 floor (REFER), 3 adds
 * TRUNCATE, 5 IOCTL_DEV, 6 the scopes. A right the kernel does not know cannot be named at all,
 * so handled and allowed sets are cut down to the ABI. A filesystem right handled and not
 * granted is denied, and every path outside a rule is denied everything handled.
 *
 * Log files have no rule. Each process opened its own description before this step, a rule
 * governs opening and not an open description, and a compromised worker gains nothing by being
 * able to open the log by name. (Phase 14's reopen goes through master.) The same holds for
 * every other descriptor a child inherits.
 *
 * The syscalls are made by hand: libc wrappers do not exist, and the constants are spelled out so
 * that the Alpine and Debian header versions do not decide what the binary can use. */
#include "proc/sandbox_priv.h"

#include "core/log.h"
#include "proc/test_hooks.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446
#endif

#define LL_CREATE_VERSION (1u << 0)
#define LL_RULE_PATH_BENEATH 1

#define LL_EXECUTE (1ull << 0)
#define LL_WRITE_FILE (1ull << 1)
#define LL_READ_FILE (1ull << 2)
#define LL_READ_DIR (1ull << 3)
#define LL_REMOVE_DIR (1ull << 4)
#define LL_REMOVE_FILE (1ull << 5)
#define LL_MAKE_CHAR (1ull << 6)
#define LL_MAKE_DIR (1ull << 7)
#define LL_MAKE_REG (1ull << 8)
#define LL_MAKE_SOCK (1ull << 9)
#define LL_MAKE_FIFO (1ull << 10)
#define LL_MAKE_BLOCK (1ull << 11)
#define LL_MAKE_SYM (1ull << 12)
#define LL_REFER (1ull << 13)	  /* ABI 2 */
#define LL_TRUNCATE (1ull << 14)  /* ABI 3 */
#define LL_IOCTL_DEV (1ull << 15) /* ABI 5 */

#define LL_ALL_V1                                                                          \
	(LL_EXECUTE | LL_WRITE_FILE | LL_READ_FILE | LL_READ_DIR | LL_REMOVE_DIR |         \
	 LL_REMOVE_FILE | LL_MAKE_CHAR | LL_MAKE_DIR | LL_MAKE_REG | LL_MAKE_SOCK |        \
	 LL_MAKE_FIFO | LL_MAKE_BLOCK | LL_MAKE_SYM)
#define LL_READ (LL_READ_FILE | LL_READ_DIR)
#define LL_WRITE                                                                           \
	(LL_READ | LL_WRITE_FILE | LL_REMOVE_DIR | LL_REMOVE_FILE | LL_MAKE_DIR |          \
	 LL_MAKE_REG | LL_REFER | LL_TRUNCATE)
/* What a rule on a file, not a directory, may name: the kernel refuses anything else there. */
#define LL_FILE_RIGHTS (LL_EXECUTE | LL_WRITE_FILE | LL_READ_FILE | LL_TRUNCATE | LL_IOCTL_DEV)

#define LL_SCOPE_ABSTRACT_UNIX (1ull << 0)
#define LL_SCOPE_SIGNAL (1ull << 1)

struct ll_attr {
	uint64_t handled_fs, handled_net, scoped;
};

struct ll_path_rule {
	uint64_t allowed;
	int32_t parent_fd;
} __attribute__((packed));

static long ll_create(const struct ll_attr *a, size_t size, unsigned flags)
{
	return syscall(SYS_landlock_create_ruleset, a, size, flags);
}

static uint64_t handled_rights(int abi)
{
	uint64_t r = LL_ALL_V1;
	if (abi >= 2)
		r |= LL_REFER;
	if (abi >= 3)
		r |= LL_TRUNCATE;
	if (abi >= 5)
		r |= LL_IOCTL_DEV;
	return r;
}

/* A path that is not there has no rule: access to it is denied, which is the safe way to be
 * wrong. It is logged because an operator will want to know why. */
static int add_rule(int ruleset, const char *path, uint64_t rights, uint64_t handled, bst_err *e)
{
	int fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0) {
		bst_log(BST_LOG_WARN, "sandbox: landlock: %s: %s: no access to it", path,
			strerror(errno));
		return 0;
	}
	struct stat st;
	if (fstat(fd, &st) != 0) {
		bst_err_set(e, "landlock: fstat %s: %s", path, strerror(errno));
		close(fd);
		return -1;
	}
	rights &= handled;
	if (!S_ISDIR(st.st_mode))
		rights &= LL_FILE_RIGHTS;
	struct ll_path_rule rule = { .allowed = rights, .parent_fd = fd };
	long rc = syscall(SYS_landlock_add_rule, ruleset, LL_RULE_PATH_BENEATH, &rule, 0);
	int err = errno;
	close(fd);
	if (rc != 0) {
		bst_err_set(e, "landlock: rule for %s: %s", path, strerror(err));
		return -1;
	}
	return 0;
}

typedef struct restrict_job {
	int ruleset;
	atomic_int failed; /* an errno */
} restrict_job;

/* Binds one thread only: every pool thread does this for itself. */
static void restrict_thread(void *arg)
{
	restrict_job *j = arg;
	if (syscall(SYS_landlock_restrict_self, j->ruleset, 0) != 0)
		atomic_store(&j->failed, errno);
}

int bst_landlock_apply(const bst_sandbox_paths *p, int *abi_out, bst_err *e)
{
	*abi_out = 0;
	long abi = ll_create(NULL, 0, LL_CREATE_VERSION);
	int err = errno;
#ifdef BST_TEST
	int inj = bst_test_sandbox_fail("landlock");
	if (inj != 0) {
		abi = -1;
		err = inj;
	}
#endif
	if (abi < 0) {
		if (err == ENOSYS || err == EOPNOTSUPP)
			return 1;
		bst_err_set(e, "landlock: %s", strerror(err));
		return -1;
	}
	uint64_t handled = handled_rights((int)abi);
	struct ll_attr attr = { .handled_fs = handled };
	size_t size = 8; /* a smaller struct on an older kernel: it refuses trailing fields */
	if (abi >= 6) {
		attr.scoped = LL_SCOPE_ABSTRACT_UNIX | LL_SCOPE_SIGNAL;
		size = sizeof attr;
	}
	int ruleset = (int)ll_create(&attr, size, 0);
	if (ruleset < 0) {
		bst_err_set(e, "landlock: ruleset: %s", strerror(errno));
		return -1;
	}
	int rc = 0;
	for (size_t i = 0; rc == 0 && i < p->nread; i++)
		rc = add_rule(ruleset, p->read[i], LL_READ, handled, e);
	for (size_t i = 0; rc == 0 && i < p->nwrite; i++)
		rc = add_rule(ruleset, p->write[i], LL_WRITE, handled, e);
	if (rc == 0) {
		restrict_job j = { .ruleset = ruleset };
		rc = bst_sandbox_each_thread(restrict_thread, &j);
		if (rc != 0)
			bst_err_set(e, "landlock: pool threads: %s", strerror(-rc));
		else if (atomic_load(&j.failed) != 0)
			bst_err_set(e, "landlock: restricting: %s", strerror(atomic_load(&j.failed)));
		rc = rc != 0 || atomic_load(&j.failed) != 0 ? -1 : 0;
	}
	close(ruleset);
	if (rc != 0)
		return -1;
	*abi_out = (int)abi;
	return 0;
}

/* Step 2 of the sandbox: optional mount, PID, IPC and UTS namespaces. See runtime.h.
 *
 * PID. A process cannot enter a new PID namespace, only its children can, so master makes one for
 * each child it forks: unshare(CLONE_NEWPID), fork, and setns back so that the next child does
 * not land in this one. One namespace per child, because the death of a namespace's init kills
 * everyone in it. libc's fork stays in the path, with what it does for malloc and threads.
 *
 * The child is then pid 1 of its namespace, which changes three things:
 *   - getppid is 0 for as long as master lives and after: bst_child_watch_master reads the
 *     channel instead.
 *   - PR_SET_PDEATHSIG still works: the signal comes from an ancestor namespace, which is not
 *     filtered the way one from inside is.
 *   - its own raise() is ignored while the disposition is the default, so the crash handler's
 *     re-raise falls through to _exit(128 + signal). Master still sees a crash.
 * Log lines say pid 1. Master's `started, pid N` line maps a tag to the pid outside.
 *
 * Mount. The child's root becomes a small read-only tmpfs holding bind mounts of the paths it
 * was given and nothing else, read paths read-only. Master's error log is not among them: a child
 * holds its own open description. /proc is not there either. The tmpfs goes on /proc for the
 * moment, the one directory every system where this can work has. */
#include "proc/sandbox_priv.h"

#include "core/log.h"
#include "proc/runtime.h"
#include "proc/test_hooks.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NEW_ROOT "/proc"
#define OLD_ROOT "/.bst-old-root"
#define ROOT_OPTS "size=1m,mode=0755"
#define BIND_FLAGS (MS_NOSUID | MS_NODEV | MS_NOEXEC)

static bool active;

bool bst_ns_active(void)
{
	return active;
}

/* ---- master ---- */

int bst_ns_setup(bst_runtime *rt, bst_err *e)
{
	const bst_cfg_sandbox *c = &rt->cfg->global.sandbox;
	rt->pidns_fd = -1;
	rt->use_ns = false;
	if (!c->namespaces)
		return 0;
	int err = 0;
	rt->pidns_fd = open("/proc/self/ns/pid", O_RDONLY | O_CLOEXEC);
	if (rt->pidns_fd < 0)
		err = errno;
	else if (unshare(CLONE_NEWPID) != 0)
		err = errno;
	else if (setns(rt->pidns_fd, CLONE_NEWPID) != 0)
		err = errno;
#ifdef BST_TEST
	if (err == 0)
		err = bst_test_sandbox_fail("namespaces");
#endif
	if (err == 0) {
		rt->use_ns = true;
		return 0;
	}
	if (rt->pidns_fd >= 0)
		close(rt->pidns_fd);
	rt->pidns_fd = -1;
	if (c->namespaces_require) {
		bst_err_set(e, "namespaces require: %s", strerror(err));
		return -1;
	}
	bst_log(BST_LOG_WARN, "sandbox: namespaces: %s: workers run without them", strerror(err));
	return 0;
}

pid_t bst_ns_fork(const bst_runtime *rt)
{
	if (!rt->use_ns)
		return fork();
	if (unshare(CLONE_NEWPID) != 0)
		return -1;
	pid_t pid = fork();
	if (pid == 0)
		return 0; /* its children would land here, and it has none */
	int err = errno;
	if (setns(rt->pidns_fd, CLONE_NEWPID) != 0)
		bst_log(BST_LOG_ERROR, "sandbox: back to master's PID namespace: %s", strerror(errno));
	errno = err;
	return pid;
}

/* ---- the child ---- */

/* mkdir -p, for the path under the new root. */
static int make_parents(char *path)
{
	for (char *p = strchr(path + 1, '/'); p != NULL; p = strchr(p + 1, '/')) {
		*p = '\0';
		int rc = mkdir(path, 0755);
		*p = '/';
		if (rc != 0 && errno != EEXIST)
			return -1;
	}
	return 0;
}

static int bind_path(const char *path, bool writable, bst_err *e)
{
	struct stat st;
	if (stat(path, &st) != 0) {
		bst_log(BST_LOG_WARN, "sandbox: namespaces: %s: %s: not in this root", path,
			strerror(errno));
		return 0;
	}
	char to[PATH_MAX];
	if (path[0] != '/' || (size_t)snprintf(to, sizeof to, NEW_ROOT "%s", path) >= sizeof to) {
		bst_err_set(e, "namespaces: bad path %s", path);
		return -1;
	}
	if (make_parents(to) != 0)
		goto fail;
	if (S_ISDIR(st.st_mode)) {
		if (mkdir(to, 0755) != 0 && errno != EEXIST)
			goto fail;
	} else {
		int fd = open(to, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
		if (fd < 0)
			goto fail;
		close(fd);
	}
	unsigned long ro = writable ? 0 : MS_RDONLY;
	if (mount(path, to, NULL, MS_BIND | MS_REC, NULL) != 0 ||
	    mount(NULL, to, NULL, MS_BIND | MS_REMOUNT | BIND_FLAGS | ro, NULL) != 0)
		goto fail;
	return 0;
fail:
	bst_err_set(e, "namespaces: mounting %s: %s", path, strerror(errno));
	return -1;
}

static int private_root(const bst_sandbox_paths *p, bst_err *e)
{
	/* Nothing below may reach the namespace master lives in. */
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0 ||
	    mount("tmpfs", NEW_ROOT, "tmpfs", BIND_FLAGS, ROOT_OPTS) != 0 ||
	    mkdir(NEW_ROOT OLD_ROOT, 0700) != 0) {
		bst_err_set(e, "namespaces: new root: %s", strerror(errno));
		return -1;
	}
	for (size_t i = 0; i < p->nread; i++)
		if (bind_path(p->read[i], false, e) != 0)
			return -1;
	for (size_t i = 0; i < p->nwrite; i++)
		if (bind_path(p->write[i], true, e) != 0)
			return -1;
	if (syscall(SYS_pivot_root, NEW_ROOT, NEW_ROOT OLD_ROOT) != 0 || chdir("/") != 0 ||
	    umount2(OLD_ROOT, MNT_DETACH) != 0 || rmdir(OLD_ROOT) != 0 ||
	    mount(NULL, "/", NULL, MS_BIND | MS_REMOUNT | BIND_FLAGS | MS_RDONLY, NULL) != 0) {
		bst_err_set(e, "namespaces: entering the new root: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int bst_ns_enter(const bst_runtime *rt, const bst_sandbox_paths *p, bst_err *e)
{
	const bst_cfg_sandbox *c = &rt->cfg->global.sandbox;
	if (!rt->use_ns)
		return 0; /* off, or master already said why not */
	int rc = 0;
	if (unshare(CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS) != 0) {
		bst_err_set(e, "namespaces: %s", strerror(errno));
		rc = -1;
	}
	if (rc == 0)
		rc = private_root(p, e);
	if (rc == 0) {
		active = true;
		return 0;
	}
	if (c->namespaces_require)
		return -1;
	bst_log(BST_LOG_WARN, "sandbox: %s: this child runs without a private root", e->msg);
	return 0;
}

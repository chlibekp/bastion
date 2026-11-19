/* Live upgrade (proc/upgrade.h): the hand-over state's format version and bounds checks, and the
 * checks on the binary an upgrade runs. bst_inherit_load reads BASTION_INHERIT once per process,
 * so each case decodes in a child of its own. */
#include "tap.h"

#include "proc/reload.h"
#include "proc/upgrade.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Codes a child reports (exit status). */
enum { OK_FRESH = 10, OK_PRESENT, REFUSED, WRONG };

/* Decodes value in a child: what came of it, and the refusal reason through a pipe. */
static int decode(const char *value, char *why, size_t cap)
{
	int p[2];
	if (pipe(p) != 0)
		return -1;
	pid_t pid = fork();
	if (pid == 0) {
		close(p[0]);
		setenv("BASTION_INHERIT", value, 1);
		const bst_inherit *inh = bst_inherit_load();
		if (getenv("BASTION_INHERIT") != NULL)
			_exit(WRONG); /* must be removed whatever came of it */
		if (inh->refused) {
			(void)!write(p[1], inh->why, strlen(inh->why));
			_exit(REFUSED);
		}
		if (inh->present && inh->generation == 7 && inh->upgrade_parent == getppid())
			_exit(OK_PRESENT);
		_exit(inh->present ? WRONG : OK_FRESH);
	}
	close(p[1]);
	ssize_t n = read(p[0], why, cap - 1);
	why[n > 0 ? n : 0] = 0;
	close(p[0]);
	int st;
	waitpid(pid, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

TEST(roundtrip_with_upgrade_parent)
{
	char why[128], *val;
	bst_inherit_out o = {.generation = 7, .pid_fd = -1, .upgrade_parent = getpid()};
	val = bst_inherit_encode(&o);
	ASSERT(val != NULL);
	ASSERT(strncmp(val, "v=1;", 4) == 0);
	ASSERT_EQ(decode(val, why, sizeof why), OK_PRESENT); /* the child's parent is us */
	free(val);
}

TEST(other_version_refused)
{
	char why[128];
	ASSERT_EQ(decode("v=999;g=7", why, sizeof why), REFUSED);
	ASSERT(strstr(why, "version 999") != NULL);
}

TEST(no_version_refused)
{
	char why[128];
	ASSERT_EQ(decode("g=7", why, sizeof why), REFUSED);
	ASSERT_EQ(decode("v=x;g=7", why, sizeof why), REFUSED);
	ASSERT_EQ(decode("v=1x;g=7", why, sizeof why), REFUSED);
}

TEST(too_long_refused)
{
	char why[128];
	size_t n = BST_INHERIT_MAX_LEN + 8;
	char *big = malloc(n + 1);
	ASSERT(big != NULL);
	memcpy(big, "v=1;g=7;", 8);
	memset(big + 8, 'x', n - 8);
	big[n] = 0;
	int rc = decode(big, why, sizeof why);
	free(big);
	ASSERT_EQ(rc, REFUSED);
}

TEST(out_of_bounds_starts_fresh)
{
	char why[128];
	/* 99999 slots (over 4096), an fd that is not open, a stdio fd: never trusted */
	ASSERT_EQ(decode("v=1;g=7;l=tcp 127.0.0.1 80|99999|5", why, sizeof why), OK_FRESH);
	ASSERT_EQ(decode("v=1;g=7;p=987654", why, sizeof why), OK_FRESH);
	ASSERT_EQ(decode("v=1;g=7;p=1", why, sizeof why), OK_FRESH);
	ASSERT_EQ(decode("v=1;g=-1", why, sizeof why), OK_FRESH);
}

/* ---- the binary ---- */

static char dir[64];

static int check_file(const char *name, mode_t mode, mode_t dmode, char *why, size_t cap)
{
	char path[128];
	snprintf(path, sizeof path, "%s/%s", dir, name);
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -2;
	(void)!write(fd, "#!/bin/sh\n", 10);
	fchmod(fd, mode);
	chmod(dir, dmode);
	int rc = bst_upgrade_check(fd, path, why, cap);
	chmod(dir, 0700);
	close(fd);
	unlink(path);
	return rc;
}

TEST(binary_checks)
{
	char why[256];
	snprintf(dir, sizeof dir, "/tmp/bst-upgrade-XXXXXX");
	ASSERT(mkdtemp(dir) != NULL);
	ASSERT_EQ(check_file("ok", 0755, 0700, why, sizeof why), 0);
	ASSERT_EQ(check_file("gw", 0775, 0700, why, sizeof why), -1);
	ASSERT(strstr(why, "writable by no one else") != NULL);
	ASSERT_EQ(check_file("ow", 0757, 0700, why, sizeof why), -1);
	ASSERT_EQ(check_file("noexec", 0644, 0700, why, sizeof why), -1);
	ASSERT(strstr(why, "not an executable") != NULL);
	ASSERT_EQ(check_file("opendir", 0755, 0777, why, sizeof why), -1);
	ASSERT(strstr(why, "directory") != NULL);
	ASSERT_EQ(check_file("sticky", 0755, 01777, why, sizeof why), 0);
	rmdir(dir);
}

TEST(pidfile_identity)
{
	char path[64], other[72];
	snprintf(path, sizeof path, "/tmp/bst-pid-XXXXXX");
	int fd = mkstemp(path);
	ASSERT(fd >= 0);
	ASSERT_EQ(bst_pidfile_write(fd, 4242), 0);
	char buf[16] = {0};
	ASSERT_EQ(pread(fd, buf, sizeof buf - 1, 0), 5);
	ASSERT_STR(buf, "4242\n");
	ASSERT(bst_pidfile_is(fd, path));
	snprintf(other, sizeof other, "%s.oldbin", path);
	ASSERT_EQ(rename(path, other), 0);
	ASSERT(!bst_pidfile_is(fd, path)); /* gone: not ours to unlink */
	ASSERT(bst_pidfile_is(fd, other));
	unlink(other);
	close(fd);
}

TAP_MAIN()

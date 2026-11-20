/* Live binary upgrade helpers: see upgrade.h. The state machine is master's (proc/master.c). */
#include "proc/upgrade.h"

#include "core/log.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_exe[PATH_MAX];

void bst_upgrade_save_exe(void)
{
	ssize_t n = readlink("/proc/self/exe", g_exe, sizeof g_exe - 1);
	if (n <= 0 || g_exe[0] != '/') {
		g_exe[0] = 0;
		return;
	}
	g_exe[n] = 0;
	/* Started from a binary already replaced on disk: the path is what an upgrade runs. */
	static const char del[] = " (deleted)";
	size_t len = (size_t)n, dl = sizeof del - 1;
	if (len > dl && strcmp(g_exe + len - dl, del) == 0)
		g_exe[len - dl] = 0;
}

const char *bst_upgrade_exe(void)
{
	return g_exe;
}

static bool owner_ok(uid_t uid)
{
	return uid == 0 || uid == geteuid();
}

int bst_upgrade_check(int fd, const char *path, char *why, size_t cap)
{
	struct stat st;
	if (fstat(fd, &st) != 0) {
		snprintf(why, cap, "%s: %s", path, strerror(errno));
		return -1;
	}
	if (!S_ISREG(st.st_mode) || (st.st_mode & S_IXUSR) == 0) {
		snprintf(why, cap, "%s: not an executable file", path);
		return -1;
	}
	if (!owner_ok(st.st_uid) || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		snprintf(why, cap, "%s: must be owned by root or uid %ld and writable by no one else",
			 path, (long)geteuid());
		return -1;
	}
	/* Its directory: anyone who may rename entries there could swap the file. */
	char dir[PATH_MAX];
	snprintf(dir, sizeof dir, "%s", path);
	char *slash = strrchr(dir, '/');
	if (slash == NULL) {
		snprintf(why, cap, "%s: not an absolute path", path);
		return -1;
	}
	if (slash == dir)
		slash[1] = 0;
	else
		*slash = 0;
	struct stat ds;
	if (stat(dir, &ds) != 0) {
		snprintf(why, cap, "%s: %s", dir, strerror(errno));
		return -1;
	}
	if (!owner_ok(ds.st_uid) ||
	    ((ds.st_mode & (S_IWGRP | S_IWOTH)) != 0 && (ds.st_mode & S_ISVTX) == 0)) {
		snprintf(why, cap, "%s: the directory must be owned by root or uid %ld and writable "
			 "by no one else (or sticky)", dir, (long)geteuid());
		return -1;
	}
	return 0;
}

int bst_upgrade_open_binary(char *why, size_t cap)
{
	if (g_exe[0] == 0) {
		snprintf(why, cap, "the path of the running binary is unknown");
		return -1;
	}
	/* Checked and run through the same open file: no swap between the two. */
	int fd = open(g_exe, O_RDONLY | O_CLOEXEC | O_NOCTTY);
	if (fd < 0) {
		snprintf(why, cap, "%s: %s", g_exe, strerror(errno));
		return -1;
	}
	if (bst_upgrade_check(fd, g_exe, why, cap) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

int bst_pidfile_write(int fd, pid_t pid)
{
	char line[32];
	int n = snprintf(line, sizeof line, "%ld\n", (long)pid);
	if (ftruncate(fd, 0) != 0)
		return -1;
	if (pwrite(fd, line, (size_t)n, 0) != n) {
		if (errno == 0)
			errno = EIO;
		return -1;
	}
	return 0;
}

bool bst_pidfile_is(int fd, const char *path)
{
	struct stat a, b;
	return fstat(fd, &a) == 0 && lstat(path, &b) == 0 && a.st_dev == b.st_dev &&
	       a.st_ino == b.st_ino;
}

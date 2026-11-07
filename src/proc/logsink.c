/* See runtime.h. */
#include "proc/runtime.h"

#include "core/log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int bst_logsink_open(const char *path, bst_err *err)
{
	if (path == NULL)
		return 2;
	int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOCTTY, 0640);
	if (fd < 0)
		bst_err_set(err, "error_log %s: %s", path, strerror(errno));
	return fd;
}

/* The pipe's capacity, asked for on the inherited pipe: the default 64 KiB drops most of a slow
 * reader's lines. A non-root process may do this to a pipe root made; failure is ignored. */
#define LOG_PIPE_BYTES (1 << 20)

/* A forked child replaces the pipe it inherited: siblings must not share one. */
static int priv[2] = { -1, -1 };

int bst_logsink_attach(int base_fd, int level)
{
	bst_log_set_splice(-1, -1);
	if (priv[0] >= 0) {
		close(priv[0]);
		close(priv[1]);
		priv[0] = priv[1] = -1;
	}
	struct stat st;
	int fd = -1;
	bool sock = false, spliced = false;
	if (fstat(base_fd, &st) == 0) {
		if (S_ISSOCK(st.st_mode)) {
			sock = true;
			fd = fcntl(base_fd, F_DUPFD_CLOEXEC, 3);
		} else {
			char path[64];
			snprintf(path, sizeof path, "/proc/self/fd/%d", base_fd);
			int flags = O_WRONLY | O_CLOEXEC | O_NOCTTY;
			fd = open(path, flags | (S_ISREG(st.st_mode) ? O_APPEND : O_NONBLOCK));
			if (fd < 0 && S_ISREG(st.st_mode)) /* O_NONBLOCK means nothing on a file */
				fd = fcntl(base_fd, F_DUPFD_CLOEXEC, 3);
			if (fd < 0 && S_ISFIFO(st.st_mode) &&
			    pipe2(priv, O_NONBLOCK | O_CLOEXEC) == 0) {
				spliced = true;
				fd = fcntl(base_fd, F_DUPFD_CLOEXEC, 3);
				if (fd >= 0)
					(void)fcntl(fd, F_SETPIPE_SZ, LOG_PIPE_BYTES);
			}
		}
	}
	bst_log_set_socket(sock && fd >= 0);
	bst_log_init(fd, level);
	if (spliced && fd >= 0)
		bst_log_set_splice(priv[1], priv[0]);
	return fd;
}

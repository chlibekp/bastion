#include "handlers/resolve.h"

#include "io/aio.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

bool bst_path_has_dotfile(const char *rel, size_t len)
{
	for (size_t i = 0; i < len; i++)
		if (rel[i] == '.' && (i == 0 || rel[i - 1] == '/'))
			return true;
	return false;
}

static int open2(int root_fd, const char *rel, unsigned long long resolve)
{
	struct open_how how;
	memset(&how, 0, sizeof how);
	how.flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY;
	how.resolve = resolve;
	return (int)syscall(SYS_openat2, root_fd, rel, &how, sizeof how);
}

static int stat_fd(int fd, struct statx *sx)
{
	if (statx(fd, "", AT_EMPTY_PATH, STATX_TYPE | STATX_MODE | STATX_INO | STATX_SIZE |
						 STATX_MTIME | STATX_UID, sx) != 0)
		return errno;
	return 0;
}

int bst_file_open_sync(int root_fd, const char *rel, bst_symlinks sl, bst_file **out)
{
	const unsigned long long base = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
	if (rel[0] == '\0')
		rel = ".";
	if (rel[0] == '/')
		return EXDEV; /* never relative to the root: refuse rather than let it reach "/" */
	int fd = open2(root_fd, rel, sl == BST_SYMLINKS_ON ? base : base | RESOLVE_NO_SYMLINKS);
	bool followed = false;
	if (fd < 0 && sl == BST_SYMLINKS_OWNER && errno == ELOOP) {
		fd = open2(root_fd, rel, base);
		followed = true;
	}
	if (fd < 0)
		return errno;
	struct statx sx;
	int rc = stat_fd(fd, &sx);
	if (rc == 0 && followed) { /* owner_match: the target must belong to the root's owner */
		struct statx rx;
		rc = stat_fd(root_fd, &rx);
		if (rc == 0 && rx.stx_uid != sx.stx_uid)
			rc = ELOOP;
	}
	if (rc != 0) {
		close(fd);
		return rc;
	}
	int64_t mt = (int64_t)sx.stx_mtime.tv_sec * 1000000000ll + (int64_t)sx.stx_mtime.tv_nsec;
	bst_file *f = bst_file_new(fd, (off_t)sx.stx_size, mt, sx.stx_ino, (mode_t)sx.stx_mode,
				   (uid_t)sx.stx_uid);
	if (f == NULL) {
		close(fd);
		return ENOMEM;
	}
	*out = f;
	return 0;
}

struct bst_file_req {
	bst_loop *loop;
	bst_ofcache *cache;
	int root_fd;
	bst_symlinks sl;
	bst_file_cb cb; /* NULL once cancelled */
	void *ud;
	bst_file *file; /* the pool's result */
	int err;
	size_t keylen;
	char *key; /* also holds rel: "<root_fd>:<sl>:<rel>" */
	const char *rel;
};

static void work(void *arg)
{
	bst_file_req *r = arg;
	r->err = bst_file_open_sync(r->root_fd, r->rel, r->sl, &r->file);
}

static void done(void *arg)
{
	bst_file_req *r = arg;
	if (r->cache != NULL) {
		uint64_t now = bst_loop_now_ms(r->loop);
		if (r->err == 0)
			bst_ofcache_put(r->cache, r->key, r->keylen, r->file, now);
		else if (r->err == ENOENT || r->err == ENOTDIR || r->err == ELOOP || r->err == EXDEV)
			bst_ofcache_put_err(r->cache, r->key, r->keylen, r->err, now);
	}
	if (r->cb != NULL)
		r->cb(r->ud, r->err == 0 ? r->file : NULL, r->err);
	else
		bst_file_unref(r->file);
	free(r->key);
	free(r);
}

bst_file_req *bst_file_open(bst_worker *w, int root_fd, bst_str rel, bst_file_policy p,
			    bst_file_cb cb, void *ud)
{
	if (!p.dotfiles_allow && bst_path_has_dotfile(rel.p, rel.len)) {
		cb(ud, NULL, ENOENT);
		return NULL;
	}
	bst_loop *loop = bst_worker_loop(w);
	bst_ofcache *cache = (bst_ofcache *)bst_worker_ofcache(w);
	bst_file_req *r = calloc(1, sizeof *r);
	size_t kl = 32 + rel.len;
	char *key = malloc(kl);
	if (r == NULL || key == NULL) {
		free(r);
		free(key);
		cb(ud, NULL, ENOMEM);
		return NULL;
	}
	size_t n = (size_t)snprintf(key, kl, "%d:%d:", root_fd, (int)p.symlinks);
	memcpy(key + n, rel.p, rel.len);
	key[n + rel.len] = '\0';
	r->rel = key + n;
	r->key = key;
	r->keylen = n + rel.len;
	r->loop = loop;
	r->cache = cache;
	r->root_fd = root_fd;
	r->sl = p.symlinks;
	r->cb = cb;
	r->ud = ud;
	if (cache != NULL) {
		int cerr = 0;
		bst_file *f = bst_ofcache_get(cache, key, r->keylen, bst_loop_now_ms(loop), &cerr);
		if (f != NULL || cerr != 0) {
			free(key);
			free(r);
			cb(ud, f, cerr);
			return NULL;
		}
	}
	int rc = bst_aio_submit(loop, work, done, r);
	if (rc != 0) {
		free(key);
		free(r);
		cb(ud, NULL, rc == -EAGAIN ? EAGAIN : ESHUTDOWN);
		return NULL;
	}
	return r;
}

void bst_file_open_cancel(bst_file_req *r)
{
	if (r != NULL)
		r->cb = NULL;
}

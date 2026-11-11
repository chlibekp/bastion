/* The open-file cache (handlers/ofcache.c) and the blocking open (handlers/resolve.c). */
#include "tap.h"

#include "handlers/ofcache.h"
#include "handlers/resolve.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bst_file *mk(int fd)
{
	bst_file *f = bst_file_new(fd, 1, 2, 3, S_IFREG | 0644, 0);
	if (f == NULL)
		abort();
	return f;
}

static int devnull(void)
{
	int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		abort();
	return fd;
}

static bool fd_open(int fd)
{
	return fcntl(fd, F_GETFD) >= 0;
}

TEST(ofcache_ttl)
{
	bst_ofcache *c = bst_ofcache_new(4, 1000, false);
	int err;
	bst_file *f = mk(devnull());
	bst_ofcache_put(c, "k", 1, f, 5000);
	bst_file *g = bst_ofcache_get(c, "k", 1, 5999, &err);
	ASSERT(g == f && err == 0);
	bst_file_unref(g);
	ASSERT(bst_ofcache_get(c, "k", 1, 6000, &err) == NULL && err == 0); /* expired */
	ASSERT_EQ(bst_ofcache_count(c), 0);
	bst_file_unref(f);
	bst_ofcache_free(c);
}

TEST(ofcache_lru)
{
	bst_ofcache *c = bst_ofcache_new(2, 1000000, false);
	int err;
	bst_file *a = mk(devnull()), *b = mk(devnull()), *d = mk(devnull());
	bst_ofcache_put(c, "a", 1, a, 0);
	bst_ofcache_put(c, "b", 1, b, 0);
	bst_file *x = bst_ofcache_get(c, "a", 1, 1, &err); /* a is now the most recent */
	bst_file_unref(x);
	bst_ofcache_put(c, "d", 1, d, 2); /* b goes */
	ASSERT(bst_ofcache_get(c, "b", 1, 3, &err) == NULL);
	x = bst_ofcache_get(c, "a", 1, 3, &err);
	ASSERT(x == a);
	bst_file_unref(x);
	x = bst_ofcache_get(c, "d", 1, 3, &err);
	ASSERT(x == d);
	bst_file_unref(x);
	ASSERT_EQ(bst_ofcache_count(c), 2);
	bst_file_unref(a);
	bst_file_unref(b);
	bst_file_unref(d);
	bst_ofcache_free(c);
}

TEST(ofcache_error_cached)
{
	bst_ofcache *c = bst_ofcache_new(4, 1000, true);
	int err = 0;
	bst_ofcache_put_err(c, "gone", 4, ENOENT, 0);
	ASSERT(bst_ofcache_get(c, "gone", 4, 10, &err) == NULL);
	ASSERT_EQ(err, ENOENT);
	ASSERT(bst_ofcache_get(c, "gone", 4, 1000, &err) == NULL && err == 0);
	bst_ofcache_free(c);
	c = bst_ofcache_new(4, 1000, false); /* errors=off: nothing is kept */
	bst_ofcache_put_err(c, "gone", 4, ENOENT, 0);
	ASSERT_EQ(bst_ofcache_count(c), 0);
	bst_ofcache_free(c);
}

TEST(ofcache_deleted_while_held)
{
	char dir[] = "build/ofcache.XXXXXX";
	ASSERT(mkdtemp(dir) != NULL);
	char path[128];
	snprintf(path, sizeof path, "%s/f", dir);
	int w = open(path, O_WRONLY | O_CREAT, 0644);
	ASSERT(write(w, "hello", 5) == 5);
	close(w);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	bst_file *f = mk(fd);
	bst_ofcache *c = bst_ofcache_new(2, 1000, false);
	bst_ofcache_put(c, "f", 1, f, 0);
	ASSERT(unlink(path) == 0); /* deleted while the cache and a request hold it */
	char buf[8];
	ASSERT(pread(fd, buf, 5, 0) == 5 && memcmp(buf, "hello", 5) == 0);
	bst_ofcache_free(c); /* the cache lets go: the request's reference keeps it */
	ASSERT(fd_open(fd));
	bst_file_unref(f); /* the last one closes it */
	ASSERT(!fd_open(fd));
	rmdir(dir);
}

static void put_file(const char *dir, const char *name, const char *text)
{
	char p[256];
	snprintf(p, sizeof p, "%s/%s", dir, name);
	FILE *f = fopen(p, "w");
	if (f == NULL)
		abort();
	fputs(text, f);
	fclose(f);
}

TEST(open_sync_beneath)
{
	char base[] = "build/resolve.XXXXXX";
	ASSERT(mkdtemp(base) != NULL);
	char www[256], p[300];
	snprintf(www, sizeof www, "%s/www", base);
	ASSERT(mkdir(www, 0755) == 0);
	put_file(base, "secret", "outside");
	put_file(www, "a", "in");
	snprintf(p, sizeof p, "%s/www/dir", base);
	ASSERT(mkdir(p, 0755) == 0);
	ASSERT(symlink("a", (snprintf(p, sizeof p, "%s/link", www), p)) == 0);
	ASSERT(symlink("../secret", (snprintf(p, sizeof p, "%s/up", www), p)) == 0);
	ASSERT(symlink("/etc/passwd", (snprintf(p, sizeof p, "%s/abs", www), p)) == 0);
	int root = open(www, O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT(root >= 0);

	bst_file *f = NULL;
	ASSERT_EQ(bst_file_open_sync(root, "a", BST_SYMLINKS_OFF, &f), 0);
	ASSERT(S_ISREG(f->mode) && f->size == 2);
	bst_file_unref(f);
	ASSERT_EQ(bst_file_open_sync(root, "dir", BST_SYMLINKS_OFF, &f), 0);
	ASSERT(S_ISDIR(f->mode));
	bst_file_unref(f);
	ASSERT_EQ(bst_file_open_sync(root, "", BST_SYMLINKS_OFF, &f), 0); /* the root itself */
	bst_file_unref(f);
	ASSERT_EQ(bst_file_open_sync(root, "link", BST_SYMLINKS_OFF, &f), ELOOP);
	ASSERT_EQ(bst_file_open_sync(root, "link", BST_SYMLINKS_ON, &f), 0);
	bst_file_unref(f);
	ASSERT_EQ(bst_file_open_sync(root, "up", BST_SYMLINKS_ON, &f), EXDEV);
	ASSERT_EQ(bst_file_open_sync(root, "abs", BST_SYMLINKS_ON, &f), EXDEV);
	ASSERT_EQ(bst_file_open_sync(root, "../secret", BST_SYMLINKS_ON, &f), EXDEV);
	ASSERT_EQ(bst_file_open_sync(root, "/etc/passwd", BST_SYMLINKS_ON, &f), EXDEV);
	ASSERT_EQ(bst_file_open_sync(root, "nope", BST_SYMLINKS_ON, &f), ENOENT);
	ASSERT_EQ(bst_file_open_sync(root, "a/x", BST_SYMLINKS_ON, &f), ENOTDIR);
	ASSERT_EQ(bst_file_open_sync(root, "link", BST_SYMLINKS_OWNER, &f), 0); /* same owner */
	bst_file_unref(f);
	close(root);
}

TEST(dotfile_components)
{
	ASSERT(bst_path_has_dotfile(".env", 4));
	ASSERT(bst_path_has_dotfile("a/.git/config", 13));
	ASSERT(bst_path_has_dotfile("a/..b", 5));
	ASSERT(!bst_path_has_dotfile("a/b.c/d.e", 9));
	ASSERT(!bst_path_has_dotfile("", 0));
}

TAP_MAIN()

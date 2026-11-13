/* The disk object store (cache/store.h): round trip, atomic publish, and every way a file on
 * disk can be wrong being a miss that deletes the file. */
#include "cache/store.h"
#include "core/arena.h"
#include "http/headers.h"
#include "tap.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char root[64];
static int rootfd = -1;
static bst_store st;

static void fresh(void)
{
	if (rootfd >= 0) {
		char cmd[128];
		snprintf(cmd, sizeof cmd, "rm -rf %s", root);
		if (system(cmd) != 0)
			abort();
		close(rootfd);
	}
	snprintf(root, sizeof root, "/tmp/bst-store-XXXXXX");
	if (mkdtemp(root) == NULL)
		abort();
	rootfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
	bst_store_init(&st, rootfd);
}

static const char HEAD[] = "content-type\0text/plain\0etag\0\"v1\"\0";
static const uint64_t TAGS[] = { 11, 22 };

static bst_sobj_meta meta(void)
{
	bst_sobj_meta m;
	memset(&m, 0, sizeof m);
	m.stored_at_ms = 123456;
	m.req_time = 100;
	m.resp_time = 101;
	m.status = 200;
	m.head = (bst_str){ HEAD, sizeof HEAD - 1 };
	m.vary = BST_S("accept-language:en\n");
	m.tags = TAGS;
	m.ntags = 2;
	m.host_hash = 77;
	return m;
}

static int put(const char *keystr, const char *body)
{
	bst_key k;
	bst_key_make((bst_str){ keystr, (uint32_t)strlen(keystr) }, &k);
	bst_sobj_meta m = meta();
	bst_swriter *w = bst_store_begin_write(&st, &k, &m);
	if (w == NULL)
		return -1;
	int rc = bst_store_write(w, body, strlen(body));
	if (rc != 0) {
		bst_store_abort(w);
		return rc;
	}
	return bst_store_commit(w);
}

static int get(const char *keystr, bst_sobj **o)
{
	bst_key k;
	bst_key_make((bst_str){ keystr, (uint32_t)strlen(keystr) }, &k);
	return bst_store_read_sync(&st, &k, o);
}

static size_t count_files(const char *sub)
{
	char p[128];
	snprintf(p, sizeof p, "%s/%s", root, sub);
	DIR *d = opendir(p);
	if (d == NULL)
		return 0;
	size_t n = 0;
	struct dirent *e;
	while ((e = readdir(d)) != NULL)
		if (e->d_name[0] != '.')
			n++;
	closedir(d);
	return n;
}

static void file_of(const char *keystr, char out[160])
{
	bst_key k;
	bst_key_make((bst_str){ keystr, (uint32_t)strlen(keystr) }, &k);
	char rel[71];
	bst_store_path(&k, rel);
	snprintf(out, 160, "%s/%s", root, rel);
}

TEST(roundtrip)
{
	fresh();
	ASSERT_EQ(put("http://a/x", "hello world"), 0);
	bst_sobj *o = NULL;
	ASSERT_EQ(get("http://a/x", &o), 0);
	ASSERT_EQ(o->m.status, 200);
	ASSERT_EQ(o->m.stored_at_ms, 123456);
	ASSERT_EQ(o->m.body_len, 11);
	ASSERT_EQ(o->body_off % BST_STORE_PAGE, 0);
	ASSERT_EQ(o->m.ntags, 2);
	ASSERT_EQ(o->m.tags[1], 22);
	ASSERT_EQ(o->m.host_hash, 77);
	ASSERT(bst_str_eq(o->m.vary, BST_S("accept-language:en\n")));
	char b[16] = { 0 };
	ASSERT_EQ(pread(o->fd, b, 11, (off_t)o->body_off), 11);
	ASSERT_STR(b, "hello world");
	bst_arena *a = bst_arena_new(4096);
	bst_headers h;
	ASSERT_EQ(bst_sobj_headers(o, &h, a), 0);
	ASSERT_EQ(h.n, 2);
	ASSERT(bst_str_eq(bst_headers_get(&h, BST_H_ETAG)->value, BST_S("\"v1\"")));
	bst_arena_free(a);
	bst_sobj_free(o);
	ASSERT_EQ(put("http://a/empty", ""), 0); /* an empty body is still an object */
	ASSERT_EQ(get("http://a/empty", &o), 0);
	ASSERT_EQ(o->m.body_len, 0);
	bst_sobj_free(o);
}

TEST(atomic_publish)
{
	fresh();
	bst_key k;
	bst_key_make(BST_S("http://a/y"), &k);
	bst_sobj_meta m = meta();
	bst_swriter *w = bst_store_begin_write(&st, &k, &m);
	ASSERT(w != NULL);
	ASSERT_EQ(bst_store_write(w, "abc", 3), 0);
	bst_sobj *o = NULL;
	ASSERT_EQ(bst_store_read_sync(&st, &k, &o), -ENOENT); /* not visible before commit */
	ASSERT_EQ(count_files("tmp"), 1);
	ASSERT_EQ(bst_store_commit(w), 0);
	ASSERT_EQ(count_files("tmp"), 0); /* renamed into place */
	ASSERT_EQ(bst_store_read_sync(&st, &k, &o), 0);
	bst_sobj_free(o);
	ASSERT_EQ(bst_store_delete(&st, &k), 0);
	ASSERT_EQ(bst_store_read_sync(&st, &k, &o), -ENOENT);
}

TEST(abort_removes_temp)
{
	fresh();
	bst_key k;
	bst_key_make(BST_S("http://a/z"), &k);
	bst_sobj_meta m = meta();
	bst_swriter *w = bst_store_begin_write(&st, &k, &m);
	ASSERT(w != NULL);
	ASSERT_EQ(bst_store_write(w, "abc", 3), 0);
	bst_store_abort(w);
	ASSERT_EQ(count_files("tmp"), 0);
	bst_sobj *o = NULL;
	ASSERT_EQ(bst_store_read_sync(&st, &k, &o), -ENOENT);
}

/* Applies f to the stored file, then expects a counted miss that deleted it. */
static int broken(void (*f)(const char *path))
{
	fresh();
	if (put("http://a/c", "0123456789") != 0)
		return 1;
	char path[160];
	file_of("http://a/c", path);
	f(path);
	bst_sobj *o = NULL;
	unsigned long long before = st.corrupt;
	if (get("http://a/c", &o) != -EBADMSG)
		return 2;
	if (st.corrupt != before + 1)
		return 3;
	if (access(path, F_OK) == 0)
		return 4; /* deleted */
	return 0;
}

static void poke(const char *path, off_t off, char c)
{
	int fd = open(path, O_WRONLY);
	if (pwrite(fd, &c, 1, off) != 1)
		abort();
	close(fd);
}

static void flip_byte(const char *path)
{
	poke(path, 100, 'X'); /* inside the hashed header */
}

static void wrong_magic(const char *path)
{
	poke(path, 0, 'Z');
}

static void short_file(const char *path)
{
	if (truncate(path, 20) != 0)
		abort();
}

static void body_short(const char *path)
{
	struct stat sb;
	stat(path, &sb);
	if (truncate(path, sb.st_size - 3) != 0)
		abort();
}

static void old_ver(const char *path)
{
	uint32_t v = 0;
	int fd = open(path, O_WRONLY);
	if (pwrite(fd, &v, 4, 8) != 4)
		abort();
	close(fd);
}

TEST(corrupt_header)
{
	ASSERT_EQ(broken(flip_byte), 0);
	ASSERT_EQ(broken(wrong_magic), 0);
	ASSERT_EQ(broken(short_file), 0);
	ASSERT_EQ(broken(body_short), 0);
}

TEST(key_mismatch)
{
	fresh();
	ASSERT_EQ(put("http://a/one", "1"), 0);
	char a[160], b[160];
	file_of("http://a/one", a);
	file_of("http://a/two", b);
	char dir[160];
	snprintf(dir, sizeof dir, "%s", b);
	*strrchr(dir, '/') = 0;
	char cmd[400];
	snprintf(cmd, sizeof cmd, "mkdir -p %s && cp %s %s", dir, a, b);
	ASSERT_EQ(system(cmd), 0);
	bst_sobj *o = NULL;
	ASSERT_EQ(get("http://a/two", &o), -EBADMSG); /* the file names another key */
	ASSERT_EQ(get("http://a/one", &o), 0);
	bst_sobj_free(o);
}

TEST(old_version)
{
	ASSERT_EQ(broken(old_ver), 0);
}

TEST(enospc)
{
	fresh();
	st.test_space = 4;
	ASSERT_EQ(put("http://a/full", "more than four bytes"), -ENOSPC);
	ASSERT_EQ(count_files("tmp"), 0); /* nothing left behind */
	bst_sobj *o = NULL;
	ASSERT_EQ(get("http://a/full", &o), -ENOENT);
	st.test_space = 0;
	/* a read-only root: begin fails, nothing is stored, nothing crashes */
	fresh();
	chmod(root, 0500);
	bst_key k;
	bst_key_make(BST_S("http://a/ro"), &k);
	bst_sobj_meta m = meta();
	bst_swriter *w = bst_store_begin_write(&st, &k, &m);
	if (geteuid() != 0)
		ASSERT(w == NULL);
	else
		bst_store_abort(w); /* root ignores the mode */
	chmod(root, 0700);
}

TAP_MAIN()

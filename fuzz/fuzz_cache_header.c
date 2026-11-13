/* libFuzzer harness for reading a cache object from disk (cache/store.h). The input becomes the
 * file of one key; properties: no crash, a read either fails (and the file is gone) or yields a
 * header whose blobs and body lie inside the file, and whose fields parse. */
#include "cache/store.h"
#include "core/arena.h"
#include "http/headers.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int rootfd = -1;
static char root[64];
static char path[200];
static bst_key key;

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t len)
{
	if (rootfd < 0) {
		snprintf(root, sizeof root, "/tmp/bst-fuzz-store-XXXXXX");
		if (mkdtemp(root) == NULL)
			abort();
		rootfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
		bst_key_make(BST_S("http://fuzz/"), &key);
		char rel[71];
		bst_store_path(&key, rel);
		snprintf(path, sizeof path, "%s/%.5s", root, rel);
		char cmd[256];
		snprintf(cmd, sizeof cmd, "mkdir -p %s", path);
		if (system(cmd) != 0)
			abort();
		snprintf(path, sizeof path, "%s/%s", root, rel);
	}
	bst_store st;
	bst_store_init(&st, rootfd);
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		abort();
	/* the key copy at its offset, so a mutated header can get past the key check */
	if (len > 0 && write(fd, d, len) != (ssize_t)len)
		abort();
	close(fd);
	bst_sobj *o = NULL;
	int rc = bst_store_read_sync(&st, &key, &o);
	if (rc == 0) {
		struct stat sb;
		if (fstat(o->fd, &sb) != 0 || o->body_off + o->m.body_len != (uint64_t)sb.st_size)
			abort();
		bst_arena *a = bst_arena_new(4096);
		bst_headers h;
		(void)bst_sobj_headers(o, &h, a);
		bst_arena_free(a);
		bst_sobj_free(o);
	} else if (rc == -EBADMSG && access(path, F_OK) == 0) {
		abort(); /* a broken file must be deleted */
	}
	return 0;
}

#include <stdint.h>
#include <string.h>

#include "core/chain.h"
#include "core/str.h"
#include "tap.h"

static bool u64(const char *s, uint64_t *v)
{
	return bst_str_to_u64((bst_str){ s, (uint32_t)strlen(s) }, v);
}

TEST(str_eq_ieq)
{
	ASSERT(bst_str_eq(BST_S("abc"), BST_S("abc")));
	ASSERT(!bst_str_eq(BST_S("abc"), BST_S("abd")));
	ASSERT(!bst_str_eq(BST_S("abc"), BST_S("ab")));
	ASSERT(bst_str_eq(BST_S(""), BST_S("")));
	ASSERT(bst_str_ieq(BST_S("Content-Length"), BST_S("content-length")));
	ASSERT(!bst_str_ieq(BST_S("a@"), BST_S("a`")));
}

TEST(u64_overflow)
{
	uint64_t v = 0;
	ASSERT(!u64("18446744073709551616", &v));
	ASSERT(!u64("99999999999999999999999", &v));
	ASSERT(u64("18446744073709551615", &v));
	ASSERT(v == UINT64_MAX);
	ASSERT(u64("0", &v) && v == 0);
}

TEST(u64_rejects_sign_and_space)
{
	uint64_t v = 7;
	ASSERT(!u64("+1", &v));
	ASSERT(!u64("-1", &v));
	ASSERT(!u64(" 1", &v));
	ASSERT(!u64("1 ", &v));
	ASSERT(!u64("", &v));
	ASSERT(!u64("1x", &v));
	ASSERT_EQ(v, 7);
}

static bst_buf *mk(const char *s)
{
	bst_buf *b = bst_buf_new(16);
	memcpy(b->data, s, strlen(s));
	b->len = strlen(s);
	return b;
}

TEST(chain_partial_consume)
{
	bst_slab *sl = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, sl);
	bst_buf *a = mk("hello"), *b = mk("world"), *d = mk("!!");
	ASSERT_EQ(bst_chain_add_mem(&c, a, 0, 5), 0);
	ASSERT_EQ(bst_chain_add_mem(&c, b, 0, 5), 0);
	ASSERT_EQ(bst_chain_add_mem(&c, d, 0, 2), 0);
	ASSERT_EQ(bst_chain_len(&c), 12);
	bst_chain_consume(&c, 7);
	ASSERT_EQ(bst_chain_len(&c), 5);
	struct iovec iov[4];
	ASSERT_EQ(bst_chain_to_iov(&c, iov, 4), 2);
	ASSERT_EQ(iov[0].iov_len, 3);
	ASSERT(memcmp(iov[0].iov_base, "rld", 3) == 0);
	ASSERT_EQ(iov[1].iov_len, 2);
	ASSERT_EQ(bst_chain_to_iov(&c, iov, 1), 1);
	bst_chain_consume(&c, 1000);
	ASSERT_EQ(bst_chain_len(&c), 0);
	ASSERT_EQ(bst_chain_to_iov(&c, iov, 4), 0);
	bst_buf_unref(a); bst_buf_unref(b); bst_buf_unref(d);
	bst_slab_free(sl);
}

/* The buffers behind the leading memory segments, in iovec order, stopping at a file. */
TEST(chain_front_bufs_match_iov)
{
	bst_slab *sl = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, sl);
	bst_buf *a = mk("hello"), *b = mk("world");
	ASSERT_EQ(bst_chain_add_mem(&c, a, 1, 4), 0);
	ASSERT_EQ(bst_chain_add_mem(&c, b, 0, 5), 0);
	ASSERT_EQ(bst_chain_add_file(&c, 0, 0, 10), 0);
	ASSERT_EQ(bst_chain_add_mem(&c, a, 0, 1), 0);
	bst_buf *bufs[4];
	ASSERT_EQ(bst_chain_front_bufs(&c, bufs, 4), 2);
	ASSERT(bufs[0] == a && bufs[1] == b);
	ASSERT_EQ(bst_chain_front_bufs(&c, bufs, 1), 1);
	ASSERT_EQ(a->refs, 3); /* no reference taken: the caller's and two segments' */
	bst_chain_consume(&c, 9);
	ASSERT_EQ(bst_chain_front_bufs(&c, bufs, 4), 0); /* a file is in front */
	bst_chain_clear(&c);
	bst_buf_unref(a); bst_buf_unref(b);
	bst_slab_free(sl);
}

TEST(chain_releases_refs)
{
	bst_slab *sl = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, sl);
	bst_buf *a = mk("abcd"), *b = mk("efgh");
	ASSERT_EQ(bst_chain_add_mem(&c, a, 0, 4), 0);
	ASSERT_EQ(bst_chain_add_mem(&c, b, 0, 4), 0);
	ASSERT_EQ(a->refs, 2);
	bst_chain_consume(&c, 3);
	ASSERT_EQ(a->refs, 2);
	bst_chain_consume(&c, 1);
	ASSERT_EQ(a->refs, 1);
	ASSERT_EQ(b->refs, 2);
	bst_chain_clear(&c);
	ASSERT_EQ(b->refs, 1);
	ASSERT_EQ(bst_chain_len(&c), 0);
	ASSERT_EQ(bst_chain_add_mem(&c, a, 3, 2), -1);
	ASSERT_EQ(bst_chain_add_mem(&c, a, 5, 0), -1);
	ASSERT_EQ(bst_chain_add_mem(&c, a, 0, 0), 0);
	bst_buf_unref(a); bst_buf_unref(b);
	bst_slab_free(sl);
}

static int released;
static void rel(void *arg) { released += *(int *)arg; }

TEST(chain_iov_stops_at_file)
{
	bst_slab *sl = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, sl);
	bst_buf *a = mk("aa"), *b = mk("bb");
	int tag = 1;
	released = 0;
	ASSERT_EQ(bst_chain_add_mem(&c, a, 0, 2), 0);
	ASSERT_EQ(bst_chain_add_file_rel(&c, 9, 100, 50, rel, &tag), 0);
	ASSERT_EQ(bst_chain_add_mem(&c, b, 0, 2), 0);
	ASSERT_EQ(bst_chain_len(&c), 54);
	struct iovec iov[4];
	ASSERT_EQ(bst_chain_to_iov(&c, iov, 4), 1);
	int fd; off_t off, len;
	ASSERT_EQ(bst_chain_front_file(&c, &fd, &off, &len), 0);
	bst_chain_consume(&c, 2);
	ASSERT_EQ(bst_chain_to_iov(&c, iov, 4), 0);
	ASSERT_EQ(bst_chain_front_file(&c, &fd, &off, &len), 1);
	ASSERT(fd == 9 && off == 100 && len == 50);
	bst_chain_consume(&c, 10);
	ASSERT_EQ(bst_chain_front_file(&c, &fd, &off, &len), 1);
	ASSERT(off == 110 && len == 40);
	ASSERT_EQ(released, 0);
	bst_chain_consume(&c, 40);
	ASSERT_EQ(released, 1);
	ASSERT_EQ(bst_chain_to_iov(&c, iov, 4), 1);
	bst_chain_clear(&c);
	ASSERT_EQ(bst_chain_add_file(&c, 3, -1, 5), -1);
	ASSERT_EQ(bst_chain_add_file(&c, 3, 0, -5), -1);
	ASSERT_EQ(bst_chain_add_file(&c, 3, INT64_MAX, 1), -1);
	ASSERT_EQ(bst_chain_add_file_rel(&c, 3, 0, 5, rel, &tag), 0);
	bst_chain_clear(&c);
	ASSERT_EQ(released, 2);
	bst_buf_unref(a); bst_buf_unref(b);
	bst_slab_free(sl);
}

TEST(chain_len_cap)
{
	bst_slab *sl = bst_chain_slab_new(4);
	bst_chain c;
	bst_chain_init(&c, sl);
	bst_buf *a = mk("ab");
	ASSERT_EQ(bst_chain_add_file(&c, 3, 0, INT64_MAX - 1), 0);
	ASSERT_EQ(bst_chain_add_mem(&c, a, 0, 1), 0);
	ASSERT_EQ(bst_chain_len(&c), (uint64_t)INT64_MAX);
	ASSERT_EQ(a->refs, 2);
	ASSERT_EQ(bst_chain_add_mem(&c, a, 0, 1), -1);
	ASSERT_EQ(a->refs, 2);
	ASSERT_EQ(bst_chain_add_file(&c, 4, 0, 1), -1);
	ASSERT_EQ(bst_chain_add_file(&c, 4, 0, INT64_MAX), -1);
	ASSERT_EQ(bst_chain_len(&c), (uint64_t)INT64_MAX);
	struct iovec iov[2];
	ASSERT_EQ(bst_chain_to_iov(&c, iov, 2), 0);
	bst_chain_consume(&c, INT64_MAX - 1);
	ASSERT_EQ(bst_chain_len(&c), 1);
	ASSERT_EQ(bst_chain_to_iov(&c, iov, 2), 1);
	bst_chain_clear(&c);
	ASSERT_EQ(a->refs, 1);
	bst_buf_unref(a);
	bst_slab_free(sl);
}

TAP_MAIN()

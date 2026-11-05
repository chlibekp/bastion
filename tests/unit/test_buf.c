#include "tap.h"

#include "core/buf.h"
#include "core/chain.h"

#include <stdlib.h>
#include <string.h>

static int released;
static bst_buf *released_buf;
static void *released_ctx;

static void hook(bst_buf *b, void *ctx)
{
	released++;
	released_buf = b;
	released_ctx = ctx;
}

TEST(new_buffer_frees_on_last_unref)
{
	bst_buf *b = bst_buf_new(32);
	ASSERT(b != NULL);
	ASSERT_EQ(b->cap, 32);
	ASSERT_EQ(b->len, 0);
	bst_buf_ref(b);
	bst_buf_unref(b);
	bst_buf_unref(b); /* ASan proves the single free */
	bst_buf_unref(NULL);
}

TEST(wrap_hook_fires_once_at_last_unref)
{
	char mem[64];
	int token;
	released = 0;
	bst_buf *b = bst_buf_wrap(mem, sizeof mem, hook, &token);
	ASSERT(b != NULL);
	ASSERT(b->data == (unsigned char *)mem);
	ASSERT_EQ(b->cap, sizeof mem);
	ASSERT_EQ(b->len, 0);
	bst_buf_ref(b);
	bst_buf_ref(b);
	bst_buf_unref(b);
	bst_buf_unref(b);
	ASSERT_EQ(released, 0);
	bst_buf_unref(b);
	ASSERT_EQ(released, 1);
	ASSERT(released_ctx == &token);
	ASSERT(released_buf != NULL);
}

TEST(init_caller_owned_header_can_be_recycled)
{
	static unsigned char mem[16];
	bst_buf hdr;
	int token;
	released = 0;
	bst_buf_init(&hdr, mem, sizeof mem, hook, &token);
	ASSERT_EQ(hdr.refs, 1);
	bst_buf_unref(&hdr);
	ASSERT_EQ(released, 1);
	ASSERT(released_buf == &hdr);
	ASSERT(released_ctx == &token);
	/* A pool takes it back and hands it out again. */
	hdr.len = 7;
	bst_buf_init(&hdr, mem, sizeof mem, hook, &token);
	ASSERT_EQ(hdr.len, 0);
	bst_buf_ref(&hdr);
	bst_buf_unref(&hdr);
	ASSERT_EQ(released, 1);
	bst_buf_unref(&hdr);
	ASSERT_EQ(released, 2);
}

TEST(hook_may_revive_a_caller_owned_header)
{
	static unsigned char mem[8];
	static bst_buf hdr;
	released = 0;
	bst_buf_init(&hdr, mem, sizeof mem, hook, NULL);
	bst_buf_unref(&hdr);
	ASSERT_EQ(released, 1);
	bst_buf_ref(&hdr); /* refs 0 -> 1 after the hook returned: pool handed it out again */
	ASSERT_EQ(hdr.refs, 1);
	bst_buf_unref(&hdr);
	ASSERT_EQ(released, 2);
}

TEST(chain_consume_releases_through_hook)
{
	char mem[16] = "0123456789abcde";
	int token;
	released = 0;
	bst_buf *b = bst_buf_wrap(mem, sizeof mem, hook, &token);
	ASSERT(b != NULL);
	b->len = 15;
	bst_slab *slab = bst_chain_slab_new(4);
	ASSERT(slab != NULL);
	bst_chain c;
	bst_chain_init(&c, slab);
	ASSERT_EQ(bst_chain_add_mem(&c, b, 0, 15), 0);
	bst_buf_unref(b); /* the chain holds the only reference now */
	ASSERT_EQ(released, 0);
	bst_chain_consume(&c, 15);
	ASSERT_EQ(released, 1);
	ASSERT(released_ctx == &token);
	bst_chain_clear(&c);
	bst_slab_free(slab);
	ASSERT_EQ(released, 1);
}

TEST(wrap_with_null_release_only_frees_header)
{
	char mem[4];
	bst_buf *b = bst_buf_wrap(mem, sizeof mem, NULL, NULL);
	ASSERT(b != NULL);
	bst_buf_unref(b);
}

TAP_MAIN()

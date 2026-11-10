#include "http/headers.h"
#include "tap.h"

#include <ctype.h>
#include <string.h>

static const struct {
	const char *name;
	bst_hdr_id id;
} known[] = {
#define X(id, name) { name, BST_H_##id },
#include "http/known_headers.def"
#undef X
};

TEST(lookup_known)
{
	ASSERT(sizeof known / sizeof known[0] == BST_H_COUNT_ - 1);
	for (size_t i = 0; i < sizeof known / sizeof known[0]; i++) {
		size_t n = strlen(known[i].name);
		char up[64], mixed[64];
		for (size_t k = 0; k <= n; k++) {
			up[k] = (char)toupper((unsigned char)known[i].name[k]);
			mixed[k] = k % 2 ? up[k] : known[i].name[k];
		}
		ASSERT_EQ(bst_hdr_lookup(known[i].name, n), known[i].id);
		ASSERT_EQ(bst_hdr_lookup(up, n), known[i].id);
		ASSERT_EQ(bst_hdr_lookup(mixed, n), known[i].id);
		ASSERT(bst_str_eq(bst_hdr_name(known[i].id), (bst_str){ known[i].name, (uint32_t)n }));
	}
}

TEST(lookup_unknown)
{
	ASSERT_EQ(bst_hdr_lookup("x-nothing", 9), BST_H_UNKNOWN);
	ASSERT_EQ(bst_hdr_lookup("", 0), BST_H_UNKNOWN);
	ASSERT_EQ(bst_hdr_lookup("hos", 3), BST_H_UNKNOWN);
	ASSERT_EQ(bst_hdr_lookup("hostt", 5), BST_H_UNKNOWN);
	ASSERT_EQ(bst_hdr_lookup("host ", 5), BST_H_UNKNOWN);
	char big[200];
	memset(big, 'a', sizeof big);
	ASSERT_EQ(bst_hdr_lookup(big, sizeof big), BST_H_UNKNOWN);
	/* every one-byte edit of a known name is unknown unless it is another known name */
	for (size_t i = 0; i < sizeof known / sizeof known[0]; i++) {
		char t[64];
		size_t n = strlen(known[i].name);
		memcpy(t, known[i].name, n + 1);
		t[n - 1] = (char)(t[n - 1] == 'z' ? 'y' : t[n - 1] + 1);
		bst_hdr_id id = bst_hdr_lookup(t, n);
		ASSERT(id == BST_H_UNKNOWN || strcmp(known[id - 1].name, t) == 0);
	}
}

TEST(add_get_case_insensitive)
{
	bst_arena *a = bst_arena_new(1024);
	bst_headers h;
	bst_headers_init(&h, a);
	ASSERT_EQ(bst_headers_add(&h, BST_S("Host"), BST_S("example.com")), 0);
	ASSERT_EQ(bst_headers_add(&h, BST_S("X-Custom"), BST_S("1")), 0);
	const bst_header *e = bst_headers_get(&h, BST_H_HOST);
	ASSERT(e != NULL && bst_str_eq(e->value, BST_S("example.com")));
	ASSERT(bst_str_eq(e->name, BST_S("Host"))); /* the received spelling is kept */
	e = bst_headers_get_name(&h, BST_S("x-CUSTOM"));
	ASSERT(e != NULL && e->id == BST_H_UNKNOWN && bst_str_eq(e->value, BST_S("1")));
	ASSERT(bst_headers_get_name(&h, BST_S("absent")) == NULL);
	ASSERT(bst_headers_get(&h, BST_H_UNKNOWN) == NULL);
	bst_arena_free(a);
}

TEST(multi_get)
{
	bst_arena *a = bst_arena_new(256);
	bst_headers h;
	bst_headers_init(&h, a);
	const char *vals[] = { "a=1", "b=2", "c=3", "d=4" };
	for (int i = 0; i < 4; i++) {
		ASSERT_EQ(bst_headers_add(&h, BST_S("Set-Cookie"), (bst_str){ vals[i], 3 }), 0);
		ASSERT_EQ(bst_headers_add(&h, BST_S("X-Between"), BST_S("x")), 0);
	}
	ASSERT_EQ(bst_headers_count(&h, BST_H_SET_COOKIE), 4);
	int i = 0;
	for (const bst_header *e = bst_headers_get(&h, BST_H_SET_COOKIE); e;
	     e = bst_headers_next(&h, e, BST_H_SET_COOKIE), i++)
		ASSERT(bst_str_eq(e->value, (bst_str){ vals[i], 3 }));
	ASSERT_EQ(i, 4);
	/* by name, for an unknown header, in order too */
	i = 0;
	for (const bst_header *e = bst_headers_get_name(&h, BST_S("x-between")); e;
	     e = bst_headers_next_name(&h, e, BST_S("x-between")))
		i++;
	ASSERT_EQ(i, 4);
	bst_arena_free(a);
}

TEST(grows_past_initial_capacity)
{
	bst_arena *a = bst_arena_new(512);
	bst_headers h;
	bst_headers_init(&h, a);
	for (int i = 0; i < 1000; i++)
		ASSERT_EQ(bst_headers_add(&h, BST_S("Via"), BST_S("1.1 p")), 0);
	ASSERT_EQ(h.n, 1000);
	ASSERT_EQ(bst_headers_count(&h, BST_H_VIA), 1000);
	bst_arena_free(a);
}

TEST(remove_and_set)
{
	bst_arena *a = bst_arena_new(512);
	bst_headers h;
	bst_headers_init(&h, a);
	bst_headers_add(&h, BST_S("Vary"), BST_S("a"));
	bst_headers_add(&h, BST_S("X-A"), BST_S("1"));
	bst_headers_add(&h, BST_S("vary"), BST_S("b"));
	bst_headers_add(&h, BST_S("X-A"), BST_S("2"));
	ASSERT_EQ(bst_headers_remove(&h, BST_H_VARY), 2);
	ASSERT_EQ(h.n, 2);
	ASSERT(bst_str_eq(h.v[0].value, BST_S("1")) && bst_str_eq(h.v[1].value, BST_S("2")));
	ASSERT_EQ(bst_headers_set(&h, BST_S("x-a"), BST_S("only")), 0);
	ASSERT_EQ(h.n, 1);
	ASSERT(bst_str_eq(h.v[0].value, BST_S("only")));
	ASSERT_EQ(bst_headers_set(&h, BST_S("Server"), BST_S("bastion")), 0);
	ASSERT_EQ(h.n, 2);
	ASSERT(bst_headers_get(&h, BST_H_SERVER) != NULL);
	ASSERT_EQ(bst_headers_remove_name(&h, BST_S("X-A")), 1);
	ASSERT_EQ(bst_headers_remove_name(&h, BST_S("nothing")), 0);
	bst_arena_free(a);
}

TEST(tchar_table)
{
	const char *rfc = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	for (int c = 0; c < 256; c++)
		ASSERT_EQ(bst_is_tchar((unsigned char)c), c != 0 && strchr(rfc, c) != NULL);
	ASSERT(bst_is_token(BST_S("Content-Type")));
	ASSERT(!bst_is_token(BST_S("")));
	ASSERT(!bst_is_token(BST_S("a b")));
	ASSERT(!bst_is_token(BST_S("a:")));
}

TEST(field_value)
{
	ASSERT(bst_is_field_value_clean(BST_S("")));
	ASSERT(bst_is_field_value_clean(BST_S("a b\tc")));
	ASSERT(bst_is_field_value_clean((bst_str){ "caf\xc3\xa9\xff", 6 })); /* obs-text */
	ASSERT(!bst_is_field_value_clean((bst_str){ "a\0b", 3 }));
	ASSERT(!bst_is_field_value_clean(BST_S("a\rb")));
	ASSERT(!bst_is_field_value_clean(BST_S("a\nb")));
	ASSERT(!bst_is_field_value_clean(BST_S("a\x7f")));
	ASSERT(!bst_is_field_value_clean(BST_S("a\x01")));
}

TAP_MAIN()

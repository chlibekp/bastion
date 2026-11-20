#include "auth/basic.h"
#include "core/b64.h"
#include "tap.h"

#include <string.h>

static bst_str S_(const char *s)
{
	return (bst_str){ s, (uint32_t)strlen(s) };
}

#define GOOD "$argon2id$v=19$m=19456,t=2,p=1$Uz7Lcwy81tiiK/i1NHrXWQ$9GoK2GZrAHJJyp8YvmciDmqSBowG0W4QuN2Oo3hELSU"

TEST(phc_parse)
{
	bst_phc h;
	ASSERT_EQ(bst_phc_parse(S_(GOOD), &h), 0);
	ASSERT_EQ(h.m_kib, 19456u);
	ASSERT_EQ(h.t, 2u);
	ASSERT_EQ(h.p, 1u);
	ASSERT_EQ(h.salt_len, 16u);
	ASSERT_EQ(h.hash_len, 32u);
	ASSERT(!bst_phc_weak(&h));
	char back[256];
	ASSERT(bst_phc_format(&h, back, sizeof back) > 0);
	ASSERT_STR(back, GOOD);
	/* invalid ones */
	const char *bad[] = {
		"$argon2i$v=19$m=19456,t=2,p=1$Uz7Lcwy81tiiK/i1NHrXWQ$9GoK2GZrAHJJyp8YvmciDmqSBowG0W4QuN2Oo3hELSU",
		"$argon2id$v=16$m=19456,t=2,p=1$Uz7Lcwy81tiiK/i1NHrXWQ$9GoK2GZrAHJJyp8YvmciDmqSBowG0W4QuN2Oo3hELSU",
		"$argon2id$v=19$m=19456,t=0,p=1$Uz7Lcwy81tiiK/i1NHrXWQ$9GoK2GZrAHJJyp8YvmciDmqSBowG0W4QuN2Oo3hELSU",
		"$argon2id$v=19$m=4,t=2,p=1$Uz7Lcwy81tiiK/i1NHrXWQ$9GoK2GZrAHJJyp8YvmciDmqSBowG0W4QuN2Oo3hELSU",
		"$argon2id$v=19$m=19456,t=2,p=1$Uz7L$9GoK2GZrAHJJyp8YvmciDmqSBowG0W4QuN2Oo3hELSU", /* short salt */
		"$argon2id$v=19$m=19456,t=2,p=1$Uz7Lcwy81tiiK/i1NHrXWQ$9GoK", /* short hash */
		"$argon2id$v=19$m=19456,t=2,p=1$Uz7Lcwy81tiiK/i1NHrXWQ==$9GoK2GZrAHJJyp8YvmciDmqSBowG0W4QuN2Oo3hELSU",
		"$argon2id$v=19$m=019456,t=2,p=1$Uz7Lcwy81tiiK/i1NHrXWQ$9GoK2GZrAHJJyp8YvmciDmqSBowG0W4QuN2Oo3hELSU",
		"$argon2id$v=19$m=99999999999,t=2,p=1$Uz7Lcwy81tiiK/i1NHrXWQ$9GoK2GZrAHJJyp8YvmciDmqSBowG0W4QuN2Oo3hELSU",
		"plain",
		"",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
		ASSERT_EQ(bst_phc_parse(S_(bad[i]), &h), -1);
	/* weak parameters parse, and are reported */
	ASSERT_EQ(bst_phc_parse(S_("$argon2id$v=19$m=1024,t=1,p=1$G2yd6PyMHnCtPmPcwmmVHA$"
				   "xv0cWwAof0BtijqkJhSivjuua1oMFfOz+m2mAI9/KLg"), &h), 0);
	ASSERT(bst_phc_weak(&h));
}

TEST(argon2id_verifies)
{
	bst_phc h;
	ASSERT_EQ(bst_phc_parse(S_(GOOD), &h), 0); /* made by `bastion passwd` for "secret-pw" */
	uint8_t out[64];
	ASSERT_EQ(bst_argon2id("secret-pw", 9, &h, out), 0);
	ASSERT_EQ(memcmp(out, h.hash, h.hash_len), 0);
	ASSERT_EQ(bst_argon2id("secret-pX", 9, &h, out), 0);
	ASSERT(memcmp(out, h.hash, h.hash_len) != 0);
	h.t = 3; /* another cost: another hash */
	ASSERT_EQ(bst_argon2id("secret-pw", 9, &h, out), 0);
	ASSERT(memcmp(out, h.hash, h.hash_len) != 0);
}

static int dec(const char *v, bst_str *u, bst_str *p, char *buf, size_t cap)
{
	return bst_basic_decode(S_(v), buf, cap, u, p);
}

TEST(decode_rules)
{
	char buf[256];
	bst_str u, p;
	ASSERT_EQ(dec("Basic YWxpY2U6c2VjcmV0LXB3", &u, &p, buf, sizeof buf), 0); /* alice:secret-pw */
	ASSERT(bst_str_eq(u, BST_S("alice")) && bst_str_eq(p, BST_S("secret-pw")));
	/* both NUL-terminated as documented (fuzz_basic): the user must not run on into ":pw" */
	ASSERT(u.p[u.len] == '\0' && p.p[p.len] == '\0');
	ASSERT_EQ(strlen(u.p), 5);
	ASSERT_EQ(dec("basic   YTpiOmM=", &u, &p, buf, sizeof buf), 0); /* a:b:c, padded */
	ASSERT(bst_str_eq(u, BST_S("a")) && bst_str_eq(p, BST_S("b:c")));
	ASSERT_EQ(dec("Basic Og==", &u, &p, buf, sizeof buf), 0); /* ":" empty both */
	ASSERT(u.len == 0 && p.len == 0);
	ASSERT_EQ(dec("Basic !!!!", &u, &p, buf, sizeof buf), -1);	  /* invalid base64 */
	ASSERT_EQ(dec("Basic YWxpY2U=", &u, &p, buf, sizeof buf), -1);   /* no colon */
	ASSERT_EQ(dec("Bearer YWxpY2U6eA==", &u, &p, buf, sizeof buf), -1);
	ASSERT_EQ(dec("Basic", &u, &p, buf, sizeof buf), -1);
	ASSERT_EQ(dec("Basic AWE6Yg==", &u, &p, buf, sizeof buf), -1);   /* control byte in user */
	ASSERT_EQ(dec("Basic YWxpY2U6c2VjcmV0LXB3", &u, &p, buf, 8), -1); /* over the cap */
	char big[6000];
	memcpy(big, "Basic ", 6);
	memset(big + 6, 'Q', sizeof big - 7);
	big[sizeof big - 1] = '\0';
	ASSERT_EQ(dec(big, &u, &p, buf, sizeof buf), -1); /* over-length: refused, no crash */
}

TEST(b64_strict)
{
	uint8_t o[16];
	ASSERT_EQ(bst_b64_decode("QQ", 2, o, sizeof o, BST_B64_URL | BST_B64_PAD_FORBIDDEN), 1);
	ASSERT_EQ(bst_b64_decode("QR", 2, o, sizeof o, BST_B64_URL | BST_B64_PAD_FORBIDDEN), -1); /* bits */
	ASSERT_EQ(bst_b64_decode("QQ==", 4, o, sizeof o, BST_B64_URL | BST_B64_PAD_FORBIDDEN), -1);
	ASSERT_EQ(bst_b64_decode("QQ==", 4, o, sizeof o, BST_B64_STD | BST_B64_PAD_OPTIONAL), 1);
	ASSERT_EQ(bst_b64_decode("QQ=", 3, o, sizeof o, BST_B64_STD | BST_B64_PAD_OPTIONAL), -1);
	ASSERT_EQ(bst_b64_decode("-_8", 3, o, sizeof o, BST_B64_URL), 2);
	ASSERT_EQ(bst_b64_decode("+/8", 3, o, sizeof o, BST_B64_URL), -1);
	ASSERT_EQ(bst_b64_decode("Q", 1, o, sizeof o, BST_B64_STD), -1);
}

TAP_MAIN()

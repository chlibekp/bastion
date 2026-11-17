#include "http/accept_encoding.h"
#include "tap.h"

#include <string.h>

static bst_encoding neg(const char *ae, uint32_t allowed)
{
	return bst_negotiate_encoding((bst_str){ ae, (uint32_t)strlen(ae) }, allowed);
}

#define ALL BST_ENC_ALL
#define GZ BST_ENC_BIT(BST_ENC_GZIP)

TEST(q_values)
{
	ASSERT_EQ(neg("br;q=0, gzip", ALL), BST_ENC_GZIP);
	ASSERT_EQ(neg("*;q=0", ALL), BST_ENC_IDENTITY);
	ASSERT_EQ(neg("gzip;q=0.5, identity", ALL), BST_ENC_IDENTITY); /* identity outweighs */
	ASSERT_EQ(neg("identity;q=0, gzip;q=0.1", ALL), BST_ENC_GZIP);
	ASSERT_EQ(neg("gzip, br", ALL), BST_ENC_BR);		  /* tie: the server's order */
	ASSERT_EQ(neg("gzip, br, zstd", ALL), BST_ENC_ZSTD);
	ASSERT_EQ(neg("gzip;q=1, br;q=0.9", ALL), BST_ENC_GZIP); /* the client's q first */
	ASSERT_EQ(neg("*", ALL), BST_ENC_ZSTD);
	ASSERT_EQ(neg("*;q=0.5, zstd;q=0", ALL), BST_ENC_BR);
	ASSERT_EQ(neg("br, zstd", GZ), BST_ENC_IDENTITY); /* none allowed */
	ASSERT_EQ(neg("GZIP ; Q=0.800", ALL), BST_ENC_GZIP);
	ASSERT_EQ(neg("x-gzip", ALL), BST_ENC_GZIP);
	ASSERT_EQ(neg("compress, deflate", ALL), BST_ENC_IDENTITY); /* not made here */
	ASSERT_EQ(neg("", ALL), BST_ENC_IDENTITY);
	ASSERT_EQ(neg("gzip,,br", ALL), BST_ENC_BR);
}

TEST(malformed_ae)
{
	const char *bad[] = { "gzip;q=2",     "gzip;q=0.1234", "gzip;q=", "gzip;q",  "gzip br",
			      "gzip;=1",      ";q=1",	       "gzip;q=1.5", "g@zip", "br;q=1.001",
			      "gzip;q=abc" };
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
		ASSERT_EQ(neg(bad[i], ALL), BST_ENC_IDENTITY);
}

TEST(encoding_names)
{
	ASSERT(bst_str_eq(bst_encoding_name(BST_ENC_BR), BST_S("br")));
	ASSERT(bst_str_eq(bst_encoding_name(BST_ENC_IDENTITY), BST_S("identity")));
}

TAP_MAIN()

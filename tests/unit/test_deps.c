/* The dependency prefix must provide what later phases rely on. */
#include "tap.h"

#include <openssl/opensslconf.h>
#include <openssl/bio.h>

TEST(openssl_has_ktls)
{
#ifdef OPENSSL_NO_KTLS
	ASSERT(0 && "OpenSSL was built without kTLS (OPENSSL_NO_KTLS)");
#endif
	ASSERT(1);
}

TAP_MAIN()

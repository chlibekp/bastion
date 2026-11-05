/* Proves the TAP harness and the build work. TAP_SELFTEST_FAIL=1 forces a failing
 * assertion so the exit-status path can be checked by hand. */
#include "tap.h"

#include <stdlib.h>

TEST(arithmetic)
{
	ASSERT(1 + 1 == 2);
	ASSERT_EQ(1 + 1, 2);
	ASSERT_STR("bastion", "bastion");
}

TEST(forced_failure_is_reported)
{
	if (getenv("TAP_SELFTEST_FAIL") != NULL)
		ASSERT_EQ(1 + 1, 3);
}

TAP_MAIN()

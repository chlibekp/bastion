/* Pure decisions of the process model: backoff, CPU choice. */
#include "proc/master.h"
#include "proc/worker.h"
#include "tap.h"

TEST(backoff_first_crash_is_immediate)
{
	ASSERT_EQ(bst_respawn_backoff_ms(0), 0);
	ASSERT_EQ(bst_respawn_backoff_ms(1), 0);
}

TEST(backoff_doubles_to_the_cap)
{
	static const uint64_t want[] = {250, 500, 1000, 2000, 4000, 8000, 16000, 30000, 30000};
	for (unsigned i = 0; i < sizeof want / sizeof want[0]; i++)
		ASSERT_EQ(bst_respawn_backoff_ms(i + 2), want[i]);
	ASSERT_EQ(BST_RESPAWN_MAX_MS, 30000);
}

TEST(backoff_never_overflows)
{
	ASSERT_EQ(bst_respawn_backoff_ms(64), BST_RESPAWN_MAX_MS);
	ASSERT_EQ(bst_respawn_backoff_ms(65), BST_RESPAWN_MAX_MS);
	ASSERT_EQ(bst_respawn_backoff_ms(4000000000u), BST_RESPAWN_MAX_MS);
}

TEST(worker_cpu_matches_listener_steering)
{
	ASSERT_EQ(bst_worker_cpu(0, true, 4), 0);
	ASSERT_EQ(bst_worker_cpu(3, true, 4), 3);
	ASSERT_EQ(bst_worker_cpu(5, true, 4), 1);
	ASSERT_EQ(bst_worker_cpu(5, false, 4), -1); /* no incoming_cpu listener: no pinning */
	ASSERT_EQ(bst_worker_cpu(5, true, 0), -1);
}

TAP_MAIN()

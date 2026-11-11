/* The 0-RTT ticket table (tls/early.c): one claim per ticket within the window, from any thread. */
#include "tap.h"
#include "tls/early.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static void *region(void)
{
	return calloc(BST_EARLY_SLOTS, sizeof(uint64_t));
}

TEST(first_claim_wins_second_loses)
{
	void *t = region();
	ASSERT(bst_early_claim(t, 0x1234567890ull, 100, 20));
	ASSERT(!bst_early_claim(t, 0x1234567890ull, 100, 20));
	ASSERT(!bst_early_claim(t, 0x1234567890ull, 119, 20));
	ASSERT(bst_early_claim(t, 0x1234567891ull, 100, 20)); /* another ticket */
	free(t);
}

TEST(a_claim_expires_after_the_window)
{
	void *t = region();
	ASSERT(bst_early_claim(t, 77, 1000, 20));
	ASSERT(!bst_early_claim(t, 77, 1020, 20)); /* still inside: kept for window + 1 seconds */
	ASSERT(bst_early_claim(t, 77, 1022, 20));  /* gone */
	free(t);
}

TEST(seconds_wrap_around_in_24_bits)
{
	void *t = region();
	uint32_t near_wrap = 0xfffff0u;
	ASSERT(bst_early_claim(t, 5, near_wrap, 20));
	ASSERT(!bst_early_claim(t, 5, near_wrap + 10, 20));
	ASSERT(bst_early_claim(t, 5, near_wrap + 30, 20)); /* across the wrap */
	free(t);
}

TEST(only_the_low_40_bits_identify_a_ticket)
{
	void *t = region();
	ASSERT(bst_early_claim(t, 0xab0000000001ull, 10, 20));
	/* the same low 40 bits, other high bits: the same ticket as far as the table can tell (the safe
	 * direction: a collision refuses early data, never grants it) */
	ASSERT(!bst_early_claim(t, 0xcd0000000001ull | (0xffull << 40), 10, 20));
	free(t);
}

TEST(a_full_neighbourhood_refuses)
{
	void *t = region();
	int accepted = 0;
	/* many tickets, all claiming: the table never says yes twice for one, and it can say no for room */
	for (uint64_t k = 1; k <= 20000; k++)
		accepted += bst_early_claim(t, k * 0x9e3779b97f4a7c15ull, 10, 20) ? 1 : 0;
	ASSERT(accepted > 15000 && accepted <= 20000);
	for (uint64_t k = 1; k <= 20000; k++)
		ASSERT(!bst_early_claim(t, k * 0x9e3779b97f4a7c15ull, 10, 20));
	free(t);
}

typedef struct {
	void *t;
	uint64_t key;
	int wins;
} job;

static void *claimer(void *arg)
{
	job *j = arg;
	if (bst_early_claim(j->t, j->key, 50, 20))
		j->wins = 1;
	return NULL;
}

TEST(concurrent_claims_have_one_winner)
{
	for (int round = 0; round < 300; round++) {
		void *t = region();
		pthread_t th[4];
		job js[4];
		for (int i = 0; i < 4; i++) {
			js[i] = (job){ t, 0x5555aaaa00ull + (uint64_t)round, 0 };
			pthread_create(&th[i], NULL, claimer, &js[i]);
		}
		int wins = 0;
		for (int i = 0; i < 4; i++) {
			pthread_join(th[i], NULL);
			wins += js[i].wins;
		}
		ASSERT_EQ(wins, 1);
		free(t);
	}
}

TAP_MAIN()

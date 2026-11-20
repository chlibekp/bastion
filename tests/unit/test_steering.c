/* The `steering ebpf` reuseport program (src/io/steering.c), run here by a small classic BPF
 * interpreter for the instructions it uses, with the receiving CPU as the only input. */
#include "io/steering.h"
#include "tap.h"

#include <linux/filter.h>
#include <stdint.h>

static int cpus_2_5_7(int slot)
{
	static const int m[] = { 2, 5, 7 };
	return m[slot % 3];
}

/* The socket index the program picks for a packet received on cpu. */
static uint32_t run(const struct sock_filter *p, long n, uint32_t cpu)
{
	uint32_t a = 0;
	for (long pc = 0; pc < n; pc++) {
		const struct sock_filter *i = &p[pc];
		switch (i->code) {
		case BPF_LD | BPF_W | BPF_ABS:
			if (i->k != (uint32_t)(SKF_AD_OFF + SKF_AD_CPU))
				return UINT32_MAX;
			a = cpu;
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
			pc += a == i->k ? i->jt : i->jf;
			break;
		case BPF_ALU | BPF_MOD | BPF_K:
			a %= i->k;
			break;
		case BPF_RET | BPF_K:
			return i->k;
		case BPF_RET | BPF_A:
			return a;
		default:
			return UINT32_MAX;
		}
	}
	return UINT32_MAX;
}

TEST(picks_the_slot_pinned_to_the_receiving_cpu)
{
	struct sock_filter p[64];
	long n = bst_steering_build(3, cpus_2_5_7, p, 64);
	ASSERT(n > 0);
	ASSERT_EQ(run(p, n, 2), 0);
	ASSERT_EQ(run(p, n, 5), 1);
	ASSERT_EQ(run(p, n, 7), 2);
}

TEST(other_cpus_fall_back_to_modulo)
{
	struct sock_filter p[64];
	long n = bst_steering_build(3, cpus_2_5_7, p, 64);
	ASSERT_EQ(run(p, n, 0), 0);
	ASSERT_EQ(run(p, n, 4), 1);
	ASSERT_EQ(run(p, n, 9), 0);
}

TEST(shared_cpu_goes_to_the_first_slot_and_limits_hold)
{
	struct sock_filter p[64];
	long n = bst_steering_build(6, cpus_2_5_7, p, 64); /* slots 3..5 repeat CPUs 2, 5, 7 */
	ASSERT_EQ(run(p, n, 5), 1);
	ASSERT_EQ(bst_steering_build(40, cpus_2_5_7, p, 64), -1); /* does not fit: refused */
	ASSERT_EQ(bst_steering_build(0, cpus_2_5_7, p, 64), -1);
}

TAP_MAIN()

/* See steering.h. */
#include "io/steering.h"

#include "ops/numa.h"

#include <errno.h>
#include <sys/socket.h>

#define STEER_MAX 4096

static int map_cpu(int slot)
{
	int c = bst_cpu_map_slot(slot);
	return c >= 0 ? c : slot;
}

long bst_steering_build(int slots, int (*cpu_of)(int slot), struct sock_filter *out, size_t cap)
{
	/* A = the receiving CPU; for each slot: if A == its CPU, return the slot; else A % slots.
	 * A CPU shared by several slots goes to the first of them. */
	size_t n = 0;
	if (slots <= 0 || cap < 3)
		return -1;
	out[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)(SKF_AD_OFF + SKF_AD_CPU));
	for (int i = 0; i < slots; i++) {
		if (n + 2 + 2 > cap)
			return -1;
		/* jeq #cpu, 0, 1 then ret #i */
		out[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)cpu_of(i), 0, 1);
		out[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, (uint32_t)i);
	}
	out[n++] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_MOD | BPF_K, (uint32_t)slots);
	out[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_A, 0);
	return (long)n;
}

int bst_steering_attach(int fd, int slots)
{
	static struct sock_filter ins[STEER_MAX];
	long n = bst_steering_build(slots, map_cpu, ins, STEER_MAX);
	if (n < 0)
		return -E2BIG;
	struct sock_fprog prog = { .len = (unsigned short)n, .filter = ins };
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &prog, sizeof prog) != 0)
		return -errno;
	return 0;
}

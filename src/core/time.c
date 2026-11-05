#include "core/time.h"

#include <time.h>

uint64_t bst_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Registers more tests than TAP_MAX_TESTS: the harness must abort with a message. */
#include "tap.h"

static void nop(void) {}

static void __attribute__((constructor)) flood(void)
{
	for (int i = 0; i < TAP_MAX_TESTS + 1; i++)
		tap_register("flood", nop);
}

TAP_MAIN()

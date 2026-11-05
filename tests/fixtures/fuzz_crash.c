/* Deliberately crashing harness: used only by test_fuzz_infra.py. */
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size >= 1 && d[0] == 'B')
		abort();
	return 0;
}

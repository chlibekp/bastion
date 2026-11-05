/* Harmless harness: used only by test_fuzz_infra.py. */
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	(void)d;
	(void)size;
	return 0;
}

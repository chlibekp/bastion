/* Dies by SIGTRAP, which libFuzzer does not catch: no reproducer is written. */
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size >= 1 && d[0] == 'B')
		__builtin_trap();
	return 0;
}

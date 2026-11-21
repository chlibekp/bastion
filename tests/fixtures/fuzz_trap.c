/* Dies by SIGTRAP, which libFuzzer does not catch: no reproducer is written. raise(), not
 * __builtin_trap(): that is SIGTRAP only on arm64 (brk); on x86_64 it is ud2, a SIGILL, which
 * libFuzzer handles and writes a reproducer for. */
#include <signal.h>
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size >= 1 && d[0] == 'B')
		raise(SIGTRAP);
	return 0;
}

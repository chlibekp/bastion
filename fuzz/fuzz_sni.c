/* libFuzzer harness for the server_name extension parser. Properties: no crash or hang; a positive
 * result is a NUL-terminated lower-case name of that length made only of host name characters, with no
 * empty label and no trailing dot. */
#include "tls/sni.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t len)
{
	char out[BST_SNI_MAX + 1];
	memset(out, 0x7f, sizeof out);
	int n = bst_tls_sni_parse(d, len, out, sizeof out);
	if (n > BST_SNI_MAX)
		__builtin_trap();
	if (n < 0)
		return 0;
	if (n == 0)
		return 0;
	if (out[n] != '\0' || strlen(out) != (size_t)n || out[0] == '.' || out[n - 1] == '.')
		__builtin_trap();
	for (int i = 0; i < n; i++) {
		char c = out[i];
		int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
		if (!ok || (c == '.' && out[i + 1] == '.'))
			__builtin_trap();
	}
	return 0;
}

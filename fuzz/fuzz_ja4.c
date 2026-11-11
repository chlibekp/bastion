/* libFuzzer harness for the ClientHello reader and the JA4 fingerprint. Properties: no crash or
 * hang on any bytes; a hello that parses either fingerprints into exactly the documented shape
 * (36 characters: transport, version, d|i, two counts, two ALPN characters, two 12-digit hashes
 * joined by underscores) or is refused, and the fingerprint is the same when computed twice. */
#include "tls/ja4.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t len)
{
	bst_client_hello ch;
	if (bst_client_hello_parse(d, len, &ch) != 0)
		return 0;
	char a[40], b[40];
	memset(a, 0x7f, sizeof a);
	if (bst_ja4_compute(&ch, 't', a) != 0)
		return 0;
	if (strlen(a) != BST_JA4_LEN || a[0] != 't' || (a[3] != 'd' && a[3] != 'i') || a[10] != '_' ||
	    a[23] != '_')
		__builtin_trap();
	for (int i = 11; i < 36; i++) {
		if (i == 23)
			continue;
		char c = a[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
			__builtin_trap();
	}
	if (bst_ja4_compute(&ch, 't', b) != 0 || strcmp(a, b) != 0)
		__builtin_trap();
	return 0;
}

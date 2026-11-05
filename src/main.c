/* bastion entry point. Phase 1 only implements --version. */
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

#ifndef BST_VERSION
#define BST_VERSION "0.0.0"
#endif

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--version") == 0) {
		printf("bastion %s (%s)\n", BST_VERSION, OpenSSL_version(OPENSSL_VERSION));
		return 0;
	}
	fprintf(stderr, "usage: bastion --version\n");
	return 2;
}

/* bastion entry point: everything else is in config/cli.c. */
#include "config/cli.h"
#include "core/alloc.h"

#include <stdio.h>

int main(int argc, char **argv)
{
	/* Before anything that can reach OpenSSL: --version calls it too. */
	if (bst_alloc_init() != 0) {
		fputs("bastion: OpenSSL allocated before mimalloc was registered\n", stderr);
		return 1;
	}
	return bst_cli_main(argc, argv);
}

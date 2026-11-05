/* bastion entry point: everything is in config/cli.c. */
#include "config/cli.h"

int main(int argc, char **argv)
{
	return bst_cli_main(argc, argv);
}

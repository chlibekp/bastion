/* Prints every syscall name on the allowlist of every role and architecture, one per line, as
 * compiled with this build's flags. */
#include "proc/seccomp.h"

#include <stdio.h>

int main(void)
{
	static char buf[16384];
	for (int a = BST_ARCH_X86_64; a <= BST_ARCH_AARCH64; a++)
		for (int r = BST_SANDBOX_WORKER; r <= BST_SANDBOX_HELPER; r++) {
			bst_seccomp_list((bst_seccomp_arch)a, (bst_sandbox_role)r, buf, sizeof buf);
			fputs(buf, stdout);
		}
	return 0;
}

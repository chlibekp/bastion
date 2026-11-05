/* A forked child returns out of a test body by mistake: it must not repeat TAP lines. */
#include "tap.h"

#include <sys/wait.h>

TEST(first)
{
	ASSERT(1);
}

TEST(forks)
{
	pid_t p = fork();
	ASSERT(p >= 0);
	if (p == 0)
		return; /* the mistake under test */
	int st;
	waitpid(p, &st, 0);
	ASSERT(WIFEXITED(st) && WEXITSTATUS(st) == 70);
}

TAP_MAIN()

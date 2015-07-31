#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sched.h>
#include <sys/wait.h>
#include <err.h>

int childfn(void *unused)
{
	printf("child ran!\n");
	unshare(CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID);
	return 0;
}

int main(int argc, char **argv)
{
	char stack[1024 * 512];
	if (argc == 2 && strcmp(argv[1], "unshare") == 0)
	{
		printf("unshare\n");
		unshare(CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID);
	} else {
		pid_t child = clone(childfn, stack + 1024 * 512, CLONE_NEWUSER|CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS, NULL);
		if (child < 0)
			err(10, "Clone failed");

		while (true)
		{
			int status = 0;
			pid_t child;
			child = waitpid(child, &status, __WALL);
			if (child < 0) err(1, "waitpid");

			if (WIFEXITED(status))
			{
				return WEXITSTATUS(status);
			} else if (WIFSIGNALED(status)) {
				fprintf(stderr, "killed by signal %d\n", WTERMSIG(status));
				return 1;
			}
		}
	}
}

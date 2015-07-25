#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <sys/wait.h>

int main()
{
	printf(" -> parent\n");
	pid_t child = fork();
	if (child < 0) err(1,"fork");
	if (!child)
	{
		printf(" -> child 1\n");
		if (!fork())
		{
			printf(" -> child 2\n");
			// let's make now a different syscall to see if it gets traced as well
			sleep(1);
			return 10;
		} else {
			while(true)
			{
				int status;
				int x = waitpid(0, &status, 0);
				if (WIFEXITED(status))
					return WEXITSTATUS(status);
			}
		}
	}

	while (true)
	{
		int status;
		int x = waitpid(0,&status,0);
		if (x < 0) err(1, "waitpid");
		if (WIFEXITED(status))
		{
			printf(" -> exiting\n");
			return WEXITSTATUS(status);
		}
	}

	return 0;
}

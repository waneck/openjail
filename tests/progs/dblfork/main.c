#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

int main()
{
	printf(" -> parent\n");
	bool parent = true;
	pid_t child = fork();
	printf(" -> fork %d\n",child);
	if (child < 0) err(1,"fork");
	if (!child)
	{
		parent = false;
		printf(" -> child 1\n");
		if (!fork())
		{
			printf(" -> child 2\n");
			// let's make now a different syscall to see if it gets traced as well
			FILE *f = fopen("/tmp/test", "w");
			fputs("file", f);
			fclose(f);
		}
	}

	int status;
	if (parent)
		waitpid(-1,&status,0);
	if (parent)
		printf(" -> exiting\n");
	return 0;
}

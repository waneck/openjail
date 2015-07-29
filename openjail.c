#include "openjail.h"
#include "helpers.h"
#include "trace.h"

#include <assert.h>
#include <dirent.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>

#define STACK_SIZE 512 * 1024

// Mark any extra file descriptors `CLOEXEC`. Only `stdin`, `stdout` and `stderr` are left open.
static void prevent_leaked_file_descriptors() 
{
	DIR *dir = opendir("/proc/self/fd");
	if (!dir) err(EXIT_FAILURE, "opendir /proc/self/fd");
	struct dirent *dp;
	while ((dp = readdir(dir))) 
	{
		char *end;
		int fd = (int)strtol(dp->d_name, &end, 10);
		if (*end == '\0' && fd > 2 && fd != dirfd(dir)) 
		{
			CHECK_POSIX(ioctl(fd, FIOCLEX));
		}
	}
	closedir(dir);
}

int main(int argc, char **argv) 
{
	prevent_leaked_file_descriptors();

	oj_args cmd_args = { .is_root = geteuid() == 0, .orig_uid = getuid(), .orig_gid = getgid() };
	if (getuid() == 0)
	{
		errx(EXIT_FAILURE, "Running a sandbox as root is not advised. "
		                   "You may either add a setsuid bit to it and run it as an unprivileged user, "
		                   "or run as an unprivileged user, and let the sandbox use CLONE_NEWUSER");
	}
	parse_args(argc,argv,&cmd_args);

	char supervisor_stack[STACK_SIZE]; //reuse our own stack for the child

	int flags = CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS;
	if (!cmd_args.allow_net)
		flags |= CLONE_NEWNET;
	if (!cmd_args.is_root)
		flags |= CLONE_NEWUSER;
	pid_t pid = clone(supervisor, supervisor_stack + STACK_SIZE, flags, &cmd_args);
	CHECK_POSIX_ARGS(pid, "clone (%d)", pid);

	if (cmd_args.learn_name)
		return trace_process(pid, cmd_args.learn_name);

	while (true)
	{
		int status = 0;
		pid_t child;
		CHECK_POSIX( (child = waitpid(pid, &status, __WALL)) );
		assert(child == pid);

		if (WIFEXITED(status))
		{
			return WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			fprintf(stderr, "killed by signal %d\n", WTERMSIG(status));
			return 1;
		}
	}
}


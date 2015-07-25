#include "helpers.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include <seccomp.h>
#include <sys/reg.h>

#define PTRACE_FLAGS \
	PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | \
	PTRACE_O_TRACEEXIT | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK

static char *get_syscall(pid_t child)
{
	errno = 0;
#ifdef __x86_64__
	long syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX);
#else
	long syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_EAX);
#endif
	if (errno) err(1,"get syscall");

	char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)syscall);
	if (!name) errx(1, "seccomp_syscall_resolve_num_arch");
	return name;
}

static int wait_for_seccomp_or_attach(pid_t child, int *child_count, pid_t *cur_child)
{
	while(true)
	{
		int status;
		/* int ret = waitpid( *child_count > 0 ? -child : child, &status, 0); */
		/* int ret = waitpid( child, &status, 0); */
		*cur_child = waitpid(-1, &status, __WALL);
		if (*cur_child < 0)
			return *cur_child;
		if (WIFSTOPPED(status))
		{
			if (WSTOPSIG(status) == SIGTRAP)
			{
				int ev = ((status >> 8) & ~SIGTRAP) >> 8;
				switch(ev)
				{
					case 0:
						printf("HERE");
						break;
					case PTRACE_EVENT_SECCOMP:
						return 1;
					case PTRACE_EVENT_EXIT:
						(*child_count)--;
						break;
					case PTRACE_EVENT_CLONE:
					case PTRACE_EVENT_FORK:
					case PTRACE_EVENT_VFORK:
						(*child_count)++;
						pid_t gchild;
						CHECK_POSIX(ptrace(PTRACE_GETEVENTMSG, *cur_child, 0, &gchild));
						printf("new process: %d\n", gchild);
						break;
					default:
						ERRX("Unexpected SIGTRAP event %x", ev);
				}
				CHECK_POSIX(ptrace(PTRACE_CONT, *cur_child, 0, 0));
			} else if (WSTOPSIG(status) == SIGSTOP) {
				CHECK_POSIX(ptrace(PTRACE_SETOPTIONS, *cur_child, 0, PTRACE_FLAGS));
				CHECK_POSIX(ptrace(PTRACE_CONT, *cur_child, 0, 0));
			} else {
				/* ERRX("Unexpected stop status: %x (%d)", status, WSTOPSIG(status)); */
				printf("Unexpected stop status: %x (%d)\n", status, WSTOPSIG(status));
			}
		} else if (WIFEXITED(status)) {
			(*child_count)--;
		} else {
				ERRX("Unexpected status: %x", status);
		}
		if (*child_count < 0)
			return 0;
		/* if (IS_SECCOMP_PTRACE_EVENT(status)) */
		/* 	return 1; */
		/* if ((WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)) */
		/* { */
		/* 	char *syscall = get_syscall(child); */
		/* 	printf("SIGTRAP %s\n",syscall); */
		/* 	CHECK_POSIX(ptrace(PTRACE_CONT, child, 0, 0)); */
		/* 	continue; */
		/* } */
		/* if (WIFEXITED(status)) */
		/* 	return 0; */
		/* fprintf(stderr, "[stopped 0x%x, 0x%x, (0x%x) (SECCOMP %x)]\n", status, WIFSTOPPED(status), WSTOPSIG(status), SIGTRAP | (PTRACE_EVENT_SECCOMP<<8)); */
		/* CHECK_POSIX(ptrace(PTRACE_CONT, child, 0, 0)); */
	}
}

static int trace_process(pid_t child, char *output)
{
	int status;
	printf("child %d\n", child);
	printf("waiting\n");
	CHECK_POSIX(waitpid(child, &status, 0));
	printf("waited\n");
	assert(WIFSTOPPED(status));
	CHECK_POSIX(ptrace(PTRACE_SETOPTIONS, child, 0, 
				PTRACE_FLAGS
	));
	CHECK_POSIX(ptrace(PTRACE_CONT, child, 0, 0));

	int child_count = 0;
	while(true)
	{
		pid_t cur_child;
		int ev = wait_for_seccomp_or_attach(child, &child_count, &cur_child);
		CHECK_POSIX(ev);
		if (!ev) break;

		char *syscall = get_syscall(cur_child);
		printf("STOPPED %s\n", syscall);
		CHECK_POSIX(ptrace(PTRACE_CONT, cur_child, 0, 0));
	}

	return 0;
}

static int child_process(int argc, char **argv)
{
	char **args = calloc((unsigned long) argc, sizeof(char *));
	for (int i = 0; i < argc; i++)
	{
		args[i] = argv[i];
	}

	CHECK_POSIX(ptrace(PTRACE_TRACEME));
	printf("raising\n");
	CHECK(raise(SIGSTOP));
	/* CHECK(kill(getpid(), SIGSTOP)); */

	prctl (PR_SET_NO_NEW_PRIVS, 1);
	printf("got back\n");
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRACE(0)); //let's trace them all
	if (NULL == ctx) errx(1, "Couldn't create seccomp filter");
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	CHECK(seccomp_load(ctx));

	printf("executing\n");
	return execvp(args[0], args + 1);
}

int main(int argc, char **argv)
{
	if (argc < 3)
		ERRX("usage: %s <output> <command> [command-arguments]\n\tif <output> already exists, the singal contents will be appended", argv[0]);

	pid_t child = fork();
	CHECK_POSIX(child);

	if (child == 0)
	{
		return child_process(argc-2, argv+2);
	} else {
		return trace_process(child, argv[1]);
	}
}

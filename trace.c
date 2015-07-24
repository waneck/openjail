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

// see ptrace(2) man
#define IS_SECCOMP_PTRACE_EVENT(status) ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8)) )

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

static int wait_for_seccomp_or_attach(pid_t child)
{
	while(true)
	{
		int status;
		int ret = waitpid(child, &status, 0);
		if (ret < 0)
			return ret;
		if (IS_SECCOMP_PTRACE_EVENT(status))
			return 1;
		if ((WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP))
		{
			/* printf("SIGTRAP\n"); */
			char *syscall = get_syscall(child);
			printf("SIGTRAP %s\n",syscall);
			CHECK_POSIX(ptrace(PTRACE_CONT, child, 0, 0));
			continue;
		}
		if (WIFEXITED(status))
			return 0;
		fprintf(stderr, "[stopped 0x%x, 0x%x, (0x%x) (SECCOMP %x)]\n", status, WIFSTOPPED(status), WSTOPSIG(status), SIGTRAP | (PTRACE_EVENT_SECCOMP<<8));
		CHECK_POSIX(ptrace(PTRACE_CONT, child, 0, 0));
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
		PTRACE_O_TRACESECCOMP
	));
	CHECK_POSIX(ptrace(PTRACE_CONT, child, 0, 0));
	while(true)
	{
		printf("waiting seccomp\n");
		int ev = wait_for_seccomp_or_attach(child);
		CHECK_POSIX(ev);
		if (!ev) break;

		char *syscall = get_syscall(child);
		printf("STOPPED %s\n", syscall);
		CHECK_POSIX(ptrace(PTRACE_CONT, child, 0, 0));
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

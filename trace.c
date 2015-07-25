#include "helpers.h"
#include "array.h"

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

static void get_syscall(pid_t child, long *normalized_id, char **name)
{
	errno = 0;
#ifdef __x86_64__
	long syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX);
#else
	long syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_EAX);
#endif
	if (errno) err(1,"get syscall");

	char *n = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)syscall);
	if (!n) errx(1, "seccomp_syscall_resolve_num_arch");
	*name = n;

	// get normalized id
	*normalized_id = syscall;
}

static long get_syscall_num(char *name)
{
	long result = seccomp_syscall_resolve_name(name);
	if (result == __NR_SCMP_ERROR) 
	{
		errx(EXIT_FAILURE, "non-existent syscall: %s", name);
	}
	return result;
}

static int wait_for_seccomp_or_attach(pid_t child, int *child_count, pid_t *cur_child, int *exit_code)
{
	while(true)
	{
		int status;
		// wait on any children of this process
		*cur_child = waitpid(-1, &status, __WALL);
		if (*cur_child < 0)
			return *cur_child;
		if (WIFSTOPPED(status))
		{
			// SIGTRAP - ptrace trapped the program
			if (WSTOPSIG(status) == SIGTRAP)
			{
				int ev = ((status >> 8) & ~SIGTRAP) >> 8;
				switch(ev)
				{
					case 0:
						break;
					case PTRACE_EVENT_SECCOMP:
						// this is a seccomp event - return back to the loop
						return 1;
					case PTRACE_EVENT_EXIT:
						// a child has exited; we'll check if all children have left later
						break;
					case PTRACE_EVENT_CLONE:
					case PTRACE_EVENT_FORK:
					case PTRACE_EVENT_VFORK:
						// we've just created another process; it will be trapped again, with waitpid
						// return its own pid
						(*child_count)++;
						break;
					default:
						ERRX("Unexpected SIGTRAP event %x", ev);
				}
				CHECK_POSIX(ptrace(PTRACE_CONT, *cur_child, 0, 0));
			} else if (WSTOPSIG(status) == SIGSTOP) {
				// trace the new child
				CHECK_POSIX(ptrace(PTRACE_SETOPTIONS, *cur_child, 0, PTRACE_FLAGS));
				CHECK_POSIX(ptrace(PTRACE_CONT, *cur_child, 0, 0));
			} else {
				// pass the signal
				CHECK_POSIX(ptrace(PTRACE_CONT, *cur_child, 0, WSTOPSIG(status)));
			}
		} else if (WIFEXITED(status)) {
			if (*cur_child == child)
				*exit_code = WEXITSTATUS(status);
			(*child_count)--;
		} else {
			ERRX("Unexpected status: %x", status);
		}
		if (*child_count < 0)
			return 0;
	}
}

static int trace_process(pid_t child, char *output)
{
	dynarr *found_syscalls = dynarr_alloc(1);
	int status;
	CHECK_POSIX(waitpid(child, &status, 0));
	assert(WIFSTOPPED(status));
	CHECK_POSIX(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_FLAGS));
	CHECK_POSIX(ptrace(PTRACE_CONT, child, 0, 0));

	if (NULL != output)
	{
		FILE *file = fopen(output, "r");
		if (NULL != file)
		{
			char *line = NULL;
			size_t len;
			ssize_t read;
			while( (read = getline(&line, &len, file)) != -1 ) 
			{
				int i = 0;
				while(true)
				{
					char cur =line[i];
					if (cur == '\n' || cur == '\r')
						line[i] = '\0';
					if (cur == '\0')
						break;
					i++;
				}
				long syscall = get_syscall_num(line);
				if (!dynarr_exists(found_syscalls, (intptr_t) syscall))
					dynarr_push(found_syscalls, (intptr_t) syscall);
			}
			free(line);
			fclose(file);
		}
	}

	FILE *file = output != NULL ? fopen(output, "a") : NULL;
	int child_count = 0, exit_code = 0;
	while(true)
	{
		pid_t cur_child;
		int ev = wait_for_seccomp_or_attach(child, &child_count, &cur_child, &exit_code);
		CHECK_POSIX(ev);
		if (!ev) break;

		long syscall;
		char *syscall_name;
		get_syscall(cur_child, &syscall, &syscall_name);
		if (!dynarr_exists(found_syscalls, (intptr_t) syscall))
		{
			printf("%s\n", syscall_name);
			dynarr_push(found_syscalls, (intptr_t) syscall);
			if (file != NULL) fprintf(file, "%s\n", syscall_name);
		}
		free(syscall_name);

		CHECK_POSIX(ptrace(PTRACE_CONT, cur_child, 0, 0));
	}

	return exit_code;
}

static int child_process(int argc, char **argv)
{
	char **args = calloc((unsigned long) argc+1, sizeof(char *));
	for (int i = 0; i < argc; i++)
	{
		args[i] = argv[i];
	}

	CHECK_POSIX(ptrace(PTRACE_TRACEME));
	CHECK(raise(SIGSTOP));
	/* CHECK(kill(getpid(), SIGSTOP)); */

	prctl (PR_SET_NO_NEW_PRIVS, 1);
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRACE(0)); //let's trace them all
	if (NULL == ctx) errx(1, "Couldn't create seccomp filter");
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
	CHECK(seccomp_load(ctx));

	CHECK_POSIX(execvp(args[0], args));
	return 1;
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

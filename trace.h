#ifndef TRACE_H_INCLUDED
#define TRACE_H_INCLUDED
#include <sys/wait.h>

#define GENERIC_SYSCALL 0
#define SYSCALL_CLONE_ARG 2

typedef struct {
	const pid_t child;
	const bool deny_report;
	const char *learn;
} trace_opts;

int child_process(int argc, char **argv);
int trace_process(trace_opts *opts);

#endif

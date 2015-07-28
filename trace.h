#ifndef TRACE_H_INCLUDED
#define TRACE_H_INCLUDED
#include <sys/wait.h>

int child_process(int argc, char **argv);
int trace_process(pid_t child, char *output);

#endif

#ifndef INCLUDED_OPENJAIL_H
#define INCLUDED_OPENJAIL_H
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct bind_list 
{
	struct bind_list *next;
	bool read_only;
	char arg[];
};

typedef struct 
{
	// arguments passed by the user
	bool mount_proc;
	bool mount_dev;
	bool mount_tmpfs;
	bool mount_minimal_dev;
	long rlimit_as;
	long rlimit_fsize;
	long rlimit_nofile;
	long rlimit_nproc;
	long rlimit_nice;
	long rlimit_cpu;
	long max_mbs;
	long mbs_check_every;
	const char *hostname;
	long timeout;
	long memory_limit;
	struct bind_list *binds;
	struct bind_list *binds_tail;
	char *syscalls;
	const char *syscalls_file;
	const char *learn_name;
	const char *root;
	char * const *cmd;

	// arguments inferred
	const bool is_root;
	const uid_t orig_uid;
	const gid_t orig_gid;
} oj_args;

// implemented on args.c

void parse_args(int argc, char **argv, oj_args *out_struct);

#endif

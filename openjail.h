#ifndef INCLUDED_OPENJAIL_H
#define INCLUDED_OPENJAIL_H
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <seccomp.h>

#define EXIT_TIMEOUT 3
#define EXIT_MB_S 4

// struct copy_list
// {
// 	struct copy_list *next;
// 	char *origin;
// 	char *dest;
// };

struct bind_list 
{
	struct bind_list *next;
	bool read_only;
	char *origin;
	char *dest;
};

typedef struct 
{
	// arguments passed by the user
	bool mount_proc;
	bool mount_dev;
	bool mount_tmpfs;
	bool mount_minimal_dev;
	long tmpfs_size;
	// struct copy_list *copies;
	// struct copy_list *copies_tail;
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


// implemented on sandbox.c

int sandbox(const oj_args *args, scmp_filter_ctx ctx);

// implemented on supervisor.c

int supervisor(void *args);

#endif

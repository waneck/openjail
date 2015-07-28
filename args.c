#include "openjail.h"
#include <getopt.h>
#include <err.h>
#include <errno.h>

static char *split_comma(char *what, char *input)
{
	char *ret = strchr(input, ',');
	if (NULL == ret)
		return NULL;
	if (ret[1] == '\0')
		errx(1, "For '%s', the argument '%s' contains ',' at the last position, which is invalid", what, input);
	ret[0] = '\0';
	return ret + 1;
}

static char *split_fromto(char *what, char *input)
{
	char *to = split_comma(what, input);
	if (NULL == to || memcmp("to=", to, 3) != 0)
		errx(1, "For '%s', the argument '%s' must include a ',to=' field", what, input);
	return to + 3;
}

static struct bind_list *bind_list_alloc(char *arg, bool extended) 
{
	struct bind_list *next = malloc(sizeof(struct bind_list));
	if (!next) err(EXIT_FAILURE, "malloc");

	next->next = NULL;
	next->origin = arg;
	next->read_only = true;
	if (extended)
	{
		next->dest = split_fromto("--bind-from", arg);
		char *rw = split_comma("--bind-from", next->dest);
		if (NULL != rw)
		{
			if (strcmp(rw, "rw"))
				next->read_only = false;
			else
				errx(1, "For '--bind-from', invalid suboption %s", rw);
		}
	} else {
		next->dest = arg;
	}
	return next;
}

/* static struct copy_list *copy_list_alloc(char *arg, bool extended)  */
/* { */
/* 	struct copy_list *next = malloc(sizeof(struct copy_list)); */
/* 	if (!next) err(EXIT_FAILURE, "malloc"); */
/*  */
/* 	next->next = NULL; */
/* 	next->origin = arg; */
/* 	if (extended) */
/* 	{ */
/* 		next->dest = split_fromto("--copy-from", arg); */
/* 		char *split = split_comma("--copy-from", next->dest); */
/* 		if (NULL != split) */
/* 			errx(1, "For '--copy-from', invalid suboption '%s'", split); */
/* 	} else { */
/* 		next->dest = NULL; */
/* 	} */
/* 	return next; */
/* } */

static long strtolx_positive(const char *s, const char *what) 
{
	char *end;
	errno = 0;
	long result = strtol(s, &end, 10);
	if (errno) errx(EXIT_FAILURE, "%s is too large", what);
	if (*end != '\0' || result < 0)
		errx(EXIT_FAILURE, "%s must be a positive integer", what);
	return result;
}

_Noreturn static void usage(FILE *out) 
{
	fprintf(out, "usage: %s [options] [root] [command ...]\n", program_invocation_short_name);
	fputs("Options:\n"
			" -h, --help                       display this help\n"
			" -v, --version                    display version\n"
			" -p, --mount-proc                 mount /proc in the container\n"
			" -d, --mount-dev-minimal          mount minimal /dev\n"
			" -D, --mount-dev                  mount /dev as devtmpfs in the container\n"
			" -T, --mount-tmpfs                mount tmpfs containers\n"
			/* " -M, --tmpfs-size                 sets the maximum combined tmpfs size (defaults to 16M)\n" */
			/* " -c, --copy=PATH                  after successful run of the program, will copy from tmpfs <PATH> to the current directory\n" */
			/* " -C, --copy-from=FROM,to=TO       same as --copy: optional interface for setting different paths for TO/FROM\n" */
			" -m, --rlimit-as=VALUE            sets the rlimit max virtual memory of the process, in bytes\n"
			"     --rlimit-cpu=VALUE           sets the rlimit max CPU time, in seconds\n"
			"     --rlimit-fsize=VALUE         sets the rlimit max file size of a single file, in bytes\n"
			"     --rlimit-nofile=VALUE        sets the rlimit max number of open files\n"
			"     --rlimit-nproc=VALUE         sets the rlimit max number of open processes\n"
			"     --rlimit-nice=VALUE          sets the rlimit min number of nice (set as 20 + nice_value. seee rlimit manpage)\n"
			" -x, --max-mbs                    sets the maximum accumulated MB-s that the process can use\n"
			" -e, --mbs-check-every            sets the internal, in ms, to check the memory usage for the MB-s accumulator\n"
			" -b, --bind=PATH                  bind mount a read-only directory in the container\n"
			" -B, --bind-from=FROM,to=TO[,rw]  same as --bind: optional interface for setting different paths for TO/FROM, and setting read/write\n"
			" -n, --hostname=NAME              the hostname/domain name to set the container to\n"
			" -t, --timeout=INTEGER            how long the container is allowed to run\n"
			" -s, --syscalls=LIST              comma-separated whitelist of syscalls\n"
			" -S, --syscalls-file=PATH         whitelist file containing one syscall name per line\n"
			" -l, --learn=PATH                 allow unwhitelisted syscalls and append them to a file\n",
		out);

	exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

void parse_args(int argc, char **argv, oj_args *out)
{
	out->mount_proc = false;
	out->mount_dev = false;
	out->mount_tmpfs = false;
	out->mount_minimal_dev = false;
	out->rlimit_as = -1;
	out->rlimit_fsize = -1;
	out->rlimit_nofile = -1;
	out->rlimit_nproc = -1;
	out->rlimit_nice = -1;
	out->rlimit_cpu = -1;
	out->max_mbs = -1;
	out->mbs_check_every = 250;
	out->hostname = "openjail";
	out->timeout = 0;
	out->binds = NULL;
	out->binds_tail = NULL;
	out->syscalls = NULL;
	out->syscalls_file = NULL;
	out->learn_name = NULL;
	/* out->copies = NULL; */
	/* out->copies_tail = NULL; */

	static const struct option opts[] = {
		{ "help",              no_argument,       0, 'h' },
		{ "version",           no_argument,       0, 'v' },
		{ "mount-proc",        no_argument,       0, 'p' },
		{ "mount-dev",         no_argument,       0, 'D' },
		{ "mount-tmpfs",       no_argument,       0, 'T' },
		{ "mount-dev-minimal", no_argument,       0, 'd' },
		/* { "tmpfs-size",        required_argument, 0, 'M' }, */
		/* { "copy",              required_argument, 0, 'c' }, */
		/* { "copy-from",         required_argument, 0, 'C' }, */
		{ "rlimit-as",         required_argument, 0, 'm' },
		{ "rlimit-fsize",      required_argument, 0, 0x201 },
		{ "rlimit-nofile",     required_argument, 0, 0x202 },
		{ "rlimit-nproc",      required_argument, 0, 0x203 },
		{ "rlimit-nice",       required_argument, 0, 0x204 },
		{ "rlimit-cpu",        required_argument, 0, 0x205 },
		{ "max-mbs",           required_argument, 0, 'x' },
		{ "mbs-check-every",   required_argument, 0, 'e' },
		{ "bind",              required_argument, 0, 'b' },
		{ "bind-from",         required_argument, 0, 'B' },
		{ "hostname",          required_argument, 0, 'n' },
		{ "timeout",           required_argument, 0, 't' },
		{ "syscalls",          required_argument, 0, 's' },
		{ "syscalls-file",     required_argument, 0, 'S' },
		{ "learn",             required_argument, 0, 'l' },
		{ 0, 0, 0, 0 }        
	};

	for (;;) 
	{
		int opt = getopt_long(argc, argv, "hvDTdpM:C:c:x:e:b:B:n:t:m:s:S:l:", opts, NULL);
		if (opt == -1)
			break;

		switch (opt) 
		{
			case 'h':
				usage(stdout);
			case 'v':
				printf("%s %s\n", program_invocation_short_name, VERSION);
				exit(0);
			case 'p':
				out->mount_proc = true;
				break;
			case 'D':
				out->mount_dev = true;
				break;
			case 'T':
				out->mount_tmpfs = true;
				break;
			case 'd':
				out->mount_minimal_dev = true;
				break;
			case 'm':
				out->rlimit_as = strtolx_positive(optarg, "rlimit-as");
				break;
			case 0x201:
				out->rlimit_fsize = strtolx_positive(optarg, "rlimit-fsize");
				break;
			case 0x202:
				out->rlimit_nofile = strtolx_positive(optarg, "rlimit-nofile");
				break;
			case 0x203:
				out->rlimit_nproc = strtolx_positive(optarg, "rlimit-nproc");
				break;
			case 0x204:
				out->rlimit_nice = strtolx_positive(optarg, "rlimit-nice");
				break;
			case 0x205:
				out->rlimit_cpu = strtolx_positive(optarg, "rlimit-cpu");
				break;
			case 'x':
				out->max_mbs = strtolx_positive(optarg, "max-mbs");
				break;
			case 'e':
				out->mbs_check_every = strtolx_positive(optarg, "mbs-check-every");
				break;
			/* case 'C': */
			/* case 'c': */
			/* 	if (out->copies)  */
			/* 	{ */
			/* 		out->copies_tail->next = copy_list_alloc(optarg, opt == 'C'); */
			/* 		out->copies_tail = out->copies_tail->next; */
			/* 	} else { */
			/* 		out->copies = out->copies_tail = copy_list_alloc(optarg, opt == 'C'); */
			/* 	} */
			/* 	break; */
			case 'b':
			case 'B':
				if (out->binds) 
				{
					out->binds_tail->next = bind_list_alloc(optarg, opt == 'B');
					out->binds_tail = out->binds_tail->next;
				} else {
					out->binds = out->binds_tail = bind_list_alloc(optarg, opt == 'B');
				}
				break;
			case 'n':
				out->hostname = optarg;
				break;
			case 't':
				out->timeout = strtolx_positive(optarg, "timeout");
				break;
			case 's':
				out->syscalls = optarg;
				break;
			case 'S':
				out->syscalls_file = optarg;
				break;
			case 'l':
				out->learn_name = optarg;
				break;
			default:
				usage(stderr);
		}
	}

	if (argc - optind < 2) 
	{
		usage(stderr);
	}

	out->root = argv[optind];
	optind++;
	out->cmd = argv + optind;
}

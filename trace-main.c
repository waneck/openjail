#include "helpers.h"
#include "trace.h"

int main(int argc, char **argv)
{
	if (argc < 2)
		ERRX("usage: %s [-o <output>] [--] <command> [command-arguments]\n\tif <output> already exists, the singal contents will be appended", argv[0]);
	char *output = NULL;
	int cur_arg = 1;
	while (cur_arg < argc && argv[cur_arg][0] == '-')
	{
		if (strcmp(argv[cur_arg], "-o") == 0)
		{
			output = argv[cur_arg + 1];
			cur_arg += 2;
		} else if (strcmp(argv[cur_arg], "--") == 0) {
			cur_arg++;
			break;
		} else {
			ERRX("unrecognized option: %s",argv[cur_arg]);
		}
	}

	pid_t child = fork();
	CHECK_POSIX(child);

	if (child == 0)
	{
		return child_process(argc-cur_arg, argv+cur_arg);
	} else {
		return trace_process(child, output);
	}
}

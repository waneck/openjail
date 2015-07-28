#include "helpers.h"
#include <err.h>
#include <errno.h>
#include <string.h>

#include <sys/mount.h>

void check(char *file, int line, int rc) 
{
	if (rc < 0) errx(EXIT_FAILURE, "%s:%d: %s", file, line, strerror(-rc));
}

__attribute__((format(printf, 4, 5))) void my_check_posix(char *file, int line, intmax_t rc, const char *fmt, ...) 
{
	va_list args;
	va_start(args, fmt);
	if (rc == -1)
	{
		fprintf(stderr, "%s:%d: ", file, line);
		verr(EXIT_FAILURE, fmt, args);
	}
	va_end(args);
}

__attribute__((format(printf, 2, 3))) bool check_eagain(intmax_t rc, const char *fmt, ...) 
{
	va_list args;
	va_start(args, fmt);
	if (rc == -1 && errno != EAGAIN) verr(EXIT_FAILURE, fmt, args);
	va_end(args);
	return rc == -1 && errno == EAGAIN;
}

char *join_path(const char *left, const char *right) 
{
	char *dst;
	CHECK_POSIX(asprintf(&dst, "%s/%s", left, right));
	return dst;
}

void mountx(char *file, int line, const char *source, const char *target, 
            const char *filesystemtype, unsigned long mountflags, const void *data) 
{
	my_check_posix(file,line,mount(source, target, filesystemtype, mountflags, data),
	               "mounting %s as %s (%s) failed", source, target, filesystemtype);
}

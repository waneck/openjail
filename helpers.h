#ifndef HELPERS_H_INCLUDED
#define HELPERS_H_INCLUDED
#include <err.h>

#define ERRX(fmt, ...) errx(1, "%s:%d: " fmt, __FILE__, __LINE__, __VA_ARGS__)
#define ERR(fmt, ...) err(1, "%s:%d: " fmt, __FILE__, __LINE__, __VA_ARGS__)
#define CHECK(arg) check(__FILE__, __LINE__, arg)
#define CHECK_POSIX(arg) if (arg < 0) err(1, "%s:%d: (%s)", __FILE__, __LINE__, #arg)
#define CHECK_POSIX_ARGS(arg, fmt, ...) if (arg < 0) err(1, "%s:%d: (%s)" fmt, __FILE__, __LINE__, #arg, __VA_ARGS__)

void check(char *file, int line, int rc);

#endif

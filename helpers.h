#ifndef HELPERS_H_INCLUDED
#define HELPERS_H_INCLUDED
#include <err.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define ERRX(fmt, ...) errx(1, "%s:%d: " fmt, __FILE__, __LINE__, __VA_ARGS__)
#define ERR(fmt, ...) err(1, "%s:%d: " fmt, __FILE__, __LINE__, __VA_ARGS__)
#define CHECK(arg) check(__FILE__, __LINE__, arg)
#define CHECK_POSIX(arg) if (arg < 0) err(1, "%s:%d: (%s)", __FILE__, __LINE__, #arg)
#define CHECK_POSIX_ARGS(arg, fmt, ...) if (arg < 0) err(1, "%s:%d: " fmt, __FILE__, __LINE__, __VA_ARGS__)
#define MOUNTX(source, target, fstype, mountflags, data) mountx(__FILE__,__LINE__,source,target,fstype,mountflags,data)

void check(char *file, int line, int rc);

__attribute__((format(printf, 4, 5))) void my_check_posix(char *file, int line, intmax_t rc, const char *fmt, ...);

__attribute__((format(printf, 2, 3))) bool check_eagain(intmax_t rc, const char *fmt, ...);

char *join_path(const char *left, const char *right);

void mountx(char *file, int line, const char *source, const char *target, 
            const char *filesystemtype, unsigned long mountflags, const void *data);

#endif

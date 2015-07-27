#include "helpers.h"
#include <string.h>
#include <err.h>

void check(char *file, int line, int rc) 
{
	if (rc < 0) errx(1, "%s:%d: %s", file, line, strerror(-rc));
}



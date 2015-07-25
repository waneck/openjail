#include "array.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>


dynarr *dynarr_alloc(unsigned int size)
{
	assert(size > 0);
	dynarr *ret = calloc(1, sizeof(dynarr));
	if (NULL == ret) return NULL;

	ret->array = calloc(size, sizeof(intptr_t));
	ret->length = size;
	return ret;
}

void dynarr_set(dynarr *self, unsigned int index, intptr_t value)
{
	assert(self != NULL);
	if (index >= self->length)
	{
		self->array = realloc(self->array, index << 1);
		assert(self->array);
		self->length = index << 1;
	}
	self->array[index] = value;
}

// gets a value
intptr_t dynarr_get(dynarr *self, unsigned int index)
{
	if (index < self->length)
		return self->array[index];
	return 0;
}

void dynarr_free(dynarr *self)
{
	free(self->array);
	free(self);
}

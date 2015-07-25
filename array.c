#include "array.h"
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
	ret->array_length = size;
	ret->length = 0;
	return ret;
}

void dynarr_set(dynarr *self, unsigned int index, intptr_t value)
{
	assert(self != NULL);
	if (index >= self->array_length)
	{
		self->array = realloc(self->array, index << 1 * sizeof(intptr_t));
		assert(self->array);
		self->array_length = index << 1;
		self->length = index + 1;
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

bool dynarr_exists(dynarr *self, intptr_t value)
{
	intptr_t *array = self->array;
	for (unsigned int i = 0; i < self->length; i++)
	{
		if (array[i] == value)
			return true;
	}
	return false;
}

void dynarr_push(dynarr *self, intptr_t value)
{
	if ((self->length + 1) >= self->array_length)
	{
		self->array = realloc(self->array, self->array_length << 1 * sizeof(intptr_t));
		assert(self->array);
		self->array_length = self->array_length << 1;
	}
	self->array[self->length] = value;
	self->length++;
}

#ifndef ARRAY_H_INCLUDED
#define ARRAY_H_INCLUDED
#include <stddef.h>
#include <stdint.h>
// A simple dynamic array implementation
// the values are always intptr_t 

typedef struct {
	intptr_t *array;
	unsigned int length;
} dynarr;

dynarr *dynarr_alloc(unsigned int size);

// sets a value; grows as needed
void dynarr_set(dynarr *self, unsigned int index, intptr_t value);

// gets a value
intptr_t dynarr_get(dynarr *self, unsigned int index);

void dynarr_free(dynarr *self);

#endif

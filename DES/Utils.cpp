// EECS 4980:805 Inside Cryptography
// DES Project
// David Carek

// This file contains tools that are useful for debugging.

#include "Utils.h"
#include <stdio.h>

// this method is for debugging purposes. it prints the binary value of the item passed
// in and works with any size value.
void printBits(size_t const size, void const * const ptr) {
	unsigned char *b = (unsigned char*)ptr;
	unsigned char byte;
	int i, j;

	for (i = size - 1; i >= 0; i--) {
		for (j = 7; j >= 0; j--) {
			byte = (b[i] >> j) & 1;
			printf("%u", byte);
		}
	}
	puts("");
}
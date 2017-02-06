#include "KeyGen.h"
#include "Macros.h"
#include <string.h>
#include "Utils.h"

BIG * generateKeys(BIG inKey) {
	// first we will set up the array that the keys will be sent back in
	BIG keyList[16] = {};
	
	// then we will run our 64 bit key through the compression p box to get the required 56 bit key.
	// the least significant 8 bits will be empty
	BIG compKey = keyCompressionPBox(inKey);

	// now that we have the 56 bit key we need to split it into 28 bit halves. keyA will contain the
	// most significant 28 bits and keyB the least significant 28 bits. 
	BIG mask = 0xfffffff;
	BIG keyA = ((compKey >> 28) & mask);
	BIG keyB = (compKey & mask);


	return keyList;
}

BIG keyCompressionPBox(BIG val) {
	BIG compressedVal = 0;
	BIG one = 1;

	printBits(sizeof(val), &val);

	if (val & (one << 63)) compressedVal |= (one << (64 - 8));
	if (val & (one << 62)) compressedVal |= (one << (64 - 16));
	if (val & (one << 61)) compressedVal |= (one << (64 - 24));
	if (val & (one << 60)) compressedVal |= (one << (64 - 56));
	if (val & (one << 59)) compressedVal |= (one << (64 - 52));
	if (val & (one << 58)) compressedVal |= (one << (64 - 44));
	if (val & (one << 57)) compressedVal |= (one << (64 - 36));
	//if (val & (1 << 56)) dropped bit
	if (val & (one << 55)) compressedVal |= (one << (64 - 7));
	if (val & (one << 54)) compressedVal |= (one << (64 - 15));
	if (val & (one << 53)) compressedVal |= (one << (64 - 23));
	if (val & (one << 52)) compressedVal |= (one << (64 - 55));
	if (val & (one << 51)) compressedVal |= (one << (64 - 51));
	if (val & (one << 50)) compressedVal |= (one << (64 - 43));
	if (val & (one << 49)) compressedVal |= (one << (64 - 35));
	//if (val & (1 << 48)) dropped bit
	if (val & (one << 47)) compressedVal |= (one << (64 - 6));
	if (val & (one << 46)) compressedVal |= (one << (64 - 14));
	if (val & (one << 45)) compressedVal |= (one << (64 - 22));
	if (val & (one << 44)) compressedVal |= (one << (64 - 54));
	if (val & (one << 43)) compressedVal |= (one << (64 - 50));
	if (val & (one << 42)) compressedVal |= (one << (64 - 42));
	if (val & (one << 41)) compressedVal |= (one << (64 - 34));
	//if (val & (1 << 40)) dropped bit
	if (val & (one << 39)) compressedVal |= (one << (64 - 5));
	if (val & (one << 38)) compressedVal |= (one << (64 - 13));
	if (val & (one << 37)) compressedVal |= (one << (64 - 21));
	if (val & (one << 36)) compressedVal |= (one << (64 - 53));
	if (val & (one << 35)) compressedVal |= (one << (64 - 49));
	if (val & (one << 34)) compressedVal |= (one << (64 - 41));
	if (val & (one << 33)) compressedVal |= (one << (64 - 33));
	//if (val & (1 << 32)) dropped bit
	if (val & (one << 31)) compressedVal |= (one << (64 - 4));
	if (val & (one << 30)) compressedVal |= (one << (64 - 12));
	if (val & (one << 29)) compressedVal |= (one << (64 - 20));
	if (val & (one << 28)) compressedVal |= (one << (64 - 28));
	if (val & (one << 27)) compressedVal |= (one << (64 - 48));
	if (val & (one << 26)) compressedVal |= (one << (64 - 40));
	if (val & (one << 25)) compressedVal |= (one << (64 - 32));
	//if (val & (1 << 24)) dropped bit
	if (val & (one << 23)) compressedVal |= (one << (64 - 3));
	if (val & (one << 22)) compressedVal |= (one << (64 - 11));
	if (val & (one << 21)) compressedVal |= (one << (64 - 19));
	if (val & (one << 20)) compressedVal |= (one << (64 - 27));
	if (val & (one << 19)) compressedVal |= (one << (64 - 47));
	if (val & (one << 18)) compressedVal |= (one << (64 - 39));
	if (val & (one << 17)) compressedVal |= (one << (64 - 31));
	//if (val & (1 << 16)) dropped bit
	if (val & (one << 15)) compressedVal |= (one << (64 - 2));
	if (val & (one << 14)) compressedVal |= (one << (64 - 10));
	if (val & (one << 13)) compressedVal |= (one << (64 - 18));
	if (val & (one << 12)) compressedVal |= (one << (64 - 26));
	if (val & (one << 11)) compressedVal |= (one << (64 - 46));
	if (val & (one << 10)) compressedVal |= (one << (64 - 38));
	if (val & (one << 9)) compressedVal |= (one << (64 - 30));
	//if (val & (1 << 8)) dropped bit
	if (val & (one << 7)) compressedVal |= (one << (64 - 1));
	if (val & (one << 6)) compressedVal |= (one << (64 - 9));
	if (val & (one << 5)) compressedVal |= (one << (64 - 17));
	if (val & (one << 4)) compressedVal |= (one << (64 - 25));
	if (val & (one << 3)) compressedVal |= (one << (64 - 45));
	if (val & (one << 2)) compressedVal |= (one << (64 - 37));
	if (val & (one << 1)) compressedVal |= (one << (64 - 29));
	//if (val & (1 << 0)) dropped bit

	compressedVal = compressedVal >> 8;
	compressedVal &= 0xffffffffffffff;

	return val;
}
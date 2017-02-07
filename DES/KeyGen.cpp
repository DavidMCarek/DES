#include "KeyGen.h"
#include "Macros.h"
#include <string.h>
#include "Utils.h"

static BIG rotateAndJoinKeys(BIG keyA, BIG keyB, int round, BIG mask);
static BIG keyCompressionPBox64_56(BIG key);
static BIG keyCompressionPBox56_48(BIG key);

BIG * generateKeys(BIG inKey) {
	// first we will set up the array that the keys will be sent back in
	BIG keyList[16] = {};
	
	// then we will run our 64 bit key through the compression p box to get the required 56 bit key.
	// the least significant 8 bits will be empty
	BIG compKey = keyCompressionPBox64_56(inKey);

	// now that we have the 56 bit key we need to split it into 28 bit halves. keyA will contain the
	// most significant 28 bits and keyB the least significant 28 bits. 
	BIG mask28 = 0xfffffff;
	BIG keyA;
	BIG keyB;
	BIG rotKey = compKey;

	for (int round = 1; round <= 16; round++) {
		// using the 28 bit mask we can isolate the necessary bits for each key
		keyA = ((rotKey >> 28) & mask28);
		keyB = (rotKey & mask28);
		rotKey = rotateAndJoinKeys(keyA, keyB, round, mask28);
		keyList[round - 1] = keyCompressionPBox56_48(rotKey);
	}


	return keyList;
}

static BIG rotateAndJoinKeys(BIG keyA, BIG keyB, int round, BIG mask) {
	// rounds 1, 2, 9, and 16 have only 1 rotate left. all other rounds rotate twice.
	// so as long as wer're not on one of the rounds where we rotate once we can just
	// perform a single rotation. the single rotation works by shifting left and then
	// copying the MSB to the LSB. after the shift MSB is the 29th bit from the right
	keyA = (keyA << 1);
	keyB = (keyB << 1);
	if (keyA & (((BIG)1) << 28)) keyA |= 1;
	if (keyB & (((BIG)1) << 28)) keyB |= 1;

	if (round != 1 && round != 2 && round != 9 && round != 16) {
		keyA = (keyA << 1);
		keyB = (keyB << 1);
		if (keyA & (((BIG)1) << 28)) keyA |= 1;
		if (keyB & (((BIG)1) << 28)) keyB |= 1;
	}

	// now that the keys are rotated we can clear out any garbage bits left over from
	// the shifting by ANDing the keys with the 28 bit mask
	keyA &= mask;
	keyB &= mask;

	// then we let keyA become the joined key by shifting then ORing with keyB
	keyA = keyA << 28;
	keyA |= keyB;

	return keyA;
}

static BIG keyCompressionPBox64_56(BIG key) {
	BIG compressedKey = 0;
	BIG one = 1;

	// in the slides bit 1 is the MSB which is the 64th bit from the right.
	// if we take a 1 and shift it 63 bits left we will be at the MSB. we can
	// decrement from there util we reach the LSB. if we subtract the new 
	// bit position from 64 we get the correct amount of bits required to 
	// shift for the permutation.
	
	if (key & (one << 63)) compressedKey |= (one << (56 - 8));
	if (key & (one << 62)) compressedKey |= (one << (56 - 16));
	if (key & (one << 61)) compressedKey |= (one << (56 - 24));
	if (key & (one << 60)) compressedKey |= (one << (56 - 56));
	if (key & (one << 59)) compressedKey |= (one << (56 - 52));
	if (key & (one << 58)) compressedKey |= (one << (56 - 44));
	if (key & (one << 57)) compressedKey |= (one << (56 - 36));
	//if (val & (1 << 56)) dropped bit
	if (key & (one << 55)) compressedKey |= (one << (56 - 7));
	if (key & (one << 54)) compressedKey |= (one << (56 - 15));
	if (key & (one << 53)) compressedKey |= (one << (56 - 23));
	if (key & (one << 52)) compressedKey |= (one << (56 - 55));
	if (key & (one << 51)) compressedKey |= (one << (56 - 51));
	if (key & (one << 50)) compressedKey |= (one << (56 - 43));
	if (key & (one << 49)) compressedKey |= (one << (56 - 35));
	//if (val & (1 << 48)) dropped bit
	if (key & (one << 47)) compressedKey |= (one << (56 - 6));
	if (key & (one << 46)) compressedKey |= (one << (56 - 14));
	if (key & (one << 45)) compressedKey |= (one << (56 - 22));
	if (key & (one << 44)) compressedKey |= (one << (56 - 54));
	if (key & (one << 43)) compressedKey |= (one << (56 - 50));
	if (key & (one << 42)) compressedKey |= (one << (56 - 42));
	if (key & (one << 41)) compressedKey |= (one << (56 - 34));
	//if (val & (1 << 40)) dropped bit
	if (key & (one << 39)) compressedKey |= (one << (56 - 5));
	if (key & (one << 38)) compressedKey |= (one << (56 - 13));
	if (key & (one << 37)) compressedKey |= (one << (56 - 21));
	if (key & (one << 36)) compressedKey |= (one << (56 - 53));
	if (key & (one << 35)) compressedKey |= (one << (56 - 49));
	if (key & (one << 34)) compressedKey |= (one << (56 - 41));
	if (key & (one << 33)) compressedKey |= (one << (56 - 33));
	//if (val & (1 << 32)) dropped bit
	if (key & (one << 31)) compressedKey |= (one << (56 - 4));
	if (key & (one << 30)) compressedKey |= (one << (56 - 12));
	if (key & (one << 29)) compressedKey |= (one << (56 - 20));
	if (key & (one << 28)) compressedKey |= (one << (56 - 28));
	if (key & (one << 27)) compressedKey |= (one << (56 - 48));
	if (key & (one << 26)) compressedKey |= (one << (56 - 40));
	if (key & (one << 25)) compressedKey |= (one << (56 - 32));
	//if (val & (1 << 24)) dropped bit
	if (key & (one << 23)) compressedKey |= (one << (56 - 3));
	if (key & (one << 22)) compressedKey |= (one << (56 - 11));
	if (key & (one << 21)) compressedKey |= (one << (56 - 19));
	if (key & (one << 20)) compressedKey |= (one << (56 - 27));
	if (key & (one << 19)) compressedKey |= (one << (56 - 47));
	if (key & (one << 18)) compressedKey |= (one << (56 - 39));
	if (key & (one << 17)) compressedKey |= (one << (56 - 31));
	//if (val & (1 << 16)) dropped bit
	if (key & (one << 15)) compressedKey |= (one << (56 - 2));
	if (key & (one << 14)) compressedKey |= (one << (56 - 10));
	if (key & (one << 13)) compressedKey |= (one << (56 - 18));
	if (key & (one << 12)) compressedKey |= (one << (56 - 26));
	if (key & (one << 11)) compressedKey |= (one << (56 - 46));
	if (key & (one << 10)) compressedKey |= (one << (56 - 38));
	if (key & (one << 9)) compressedKey |= (one << (56 - 30));
	//if (val & (1 << 8)) dropped bit
	if (key & (one << 7)) compressedKey |= (one << (56 - 1));
	if (key & (one << 6)) compressedKey |= (one << (56 - 9));
	if (key & (one << 5)) compressedKey |= (one << (56 - 17));
	if (key & (one << 4)) compressedKey |= (one << (56 - 25));
	if (key & (one << 3)) compressedKey |= (one << (56 - 45));
	if (key & (one << 2)) compressedKey |= (one << (56 - 37));
	if (key & (one << 1)) compressedKey |= (one << (56 - 29));
	//if (val & (1 << 0)) dropped bit

	return compressedKey;
}

static BIG keyCompressionPBox56_48(BIG key) {
	// this is the final p box for the the key. this pbox functions the same 
	// as the first
	BIG one = 1;
	BIG compressedKey = 0;

	if (key & (one << 55)) compressedKey |= (one << (48 - 5));
	if (key & (one << 54)) compressedKey |= (one << (48 - 24));
	if (key & (one << 53)) compressedKey |= (one << (48 - 7));
	if (key & (one << 52)) compressedKey |= (one << (48 - 16));
	if (key & (one << 51)) compressedKey |= (one << (48 - 6));
	if (key & (one << 50)) compressedKey |= (one << (48 - 10));
	if (key & (one << 49)) compressedKey |= (one << (48 - 20));
	if (key & (one << 48)) compressedKey |= (one << (48 - 18));
	//if (key & (one << 47)) dropped bit
	if (key & (one << 46)) compressedKey |= (one << (48 - 12));
	if (key & (one << 45)) compressedKey |= (one << (48 - 3));
	if (key & (one << 44)) compressedKey |= (one << (48 - 15));
	if (key & (one << 43)) compressedKey |= (one << (48 - 23));
	if (key & (one << 42)) compressedKey |= (one << (48 - 1));
	if (key & (one << 41)) compressedKey |= (one << (48 - 9));
	if (key & (one << 40)) compressedKey |= (one << (48 - 19));
	if (key & (one << 39)) compressedKey |= (one << (48 - 2));
	//if (key & (one << 38)) dropped bit
	if (key & (one << 37)) compressedKey |= (one << (48 - 14));
	if (key & (one << 36)) compressedKey |= (one << (48 - 22));
	if (key & (one << 35)) compressedKey |= (one << (48 - 11));
	//if (key & (one << 34)) dropped bit
	if (key & (one << 33)) compressedKey |= (one << (48 - 13));
	if (key & (one << 32)) compressedKey |= (one << (48 - 4));
	//if (key & (one << 31)) dropped bit
	if (key & (one << 30)) compressedKey |= (one << (48 - 17));
	if (key & (one << 29)) compressedKey |= (one << (48 - 21));
	if (key & (one << 28)) compressedKey |= (one << (48 - 8));
	if (key & (one << 27)) compressedKey |= (one << (48 - 47));
	if (key & (one << 26)) compressedKey |= (one << (48 - 31));
	if (key & (one << 25)) compressedKey |= (one << (48 - 27));
	if (key & (one << 24)) compressedKey |= (one << (48 - 48));
	if (key & (one << 23)) compressedKey |= (one << (48 - 35));
	if (key & (one << 22)) compressedKey |= (one << (48 - 41));
	//if (key & (one << 21)) dropped bit
	if (key & (one << 20)) compressedKey |= (one << (48 - 46));
	if (key & (one << 19)) compressedKey |= (one << (48 - 28));
	//if (key & (one << 18)) dropped bit
	if (key & (one << 17)) compressedKey |= (one << (48 - 39));
	if (key & (one << 16)) compressedKey |= (one << (48 - 32));
	if (key & (one << 15)) compressedKey |= (one << (48 - 25));
	if (key & (one << 14)) compressedKey |= (one << (48 - 44));
	//if (key & (one << 13)) dropped bit
	if (key & (one << 12)) compressedKey |= (one << (48 - 37));
	if (key & (one << 11)) compressedKey |= (one << (48 - 34));
	if (key & (one << 10)) compressedKey |= (one << (48 - 43));
	if (key & (one << 9)) compressedKey |= (one << (48 - 29));
	if (key & (one << 8)) compressedKey |= (one << (48 - 36));
	if (key & (one << 7)) compressedKey |= (one << (48 - 38));
	if (key & (one << 6)) compressedKey |= (one << (48 - 45));
	if (key & (one << 5)) compressedKey |= (one << (48 - 33));
	if (key & (one << 4)) compressedKey |= (one << (48 - 26));
	if (key & (one << 3)) compressedKey |= (one << (48 - 42));
	//if (key & (one << 2)) dropped bit
	if (key & (one << 1)) compressedKey |= (one << (48 - 30));
	if (key & (one << 0)) compressedKey |= (one << (48 - 40));

	return compressedKey;
}
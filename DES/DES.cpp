#include "DES.h"

// this is a 
static const unsigned char s_box_substitution[8][64] = { 
	{ 
		14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
		4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13, 
	},
	{ 
		15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
		0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2, 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9, 
	},
	{ 
		10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
		13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12, 
	},
	{ 
		7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
		10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14, 
	},
	{ 
		2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
		4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3, 
	},
	{ 
		12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
		9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13, 
	},
	{ 
		4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
		1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12, 
	},
	{ 
		13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
		7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11, 
	}, 
};

static BIG initialPermutation(BIG block);
static BIG finalPermutation(BIG block);
static BIG blockExpansionPBox32_48(BIG block);
static BIG sBoxes48_32(BIG expandedHalf);
static BIG straightPBox32_32(BIG halfBlock);

// this method runs all of the internals to DES in the order listed below
//
// initial permutation
// round 1-16
// final permutation
//
// round_i details
//	right half
//		sent through expansion p box
//		XORed with key_i
//		result sent through s box array
//		then through straight p box
//		result is XORed with left half to become right half
//		right half becomes left half
BIG runDES(BIG keys[], BIG block, bool encrypting) {

	block = initialPermutation(block);
	BIG mask48 = 0xffffffffffff;
	BIG mask32 = 0xffffffff;
	BIG rightHalf = block & mask32;
	BIG tempLeftHalf;
	BIG leftHalf = block >> 32;

	if (encrypting) {

		BIG expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[0]) & mask48;
		BIG halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[1]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[2]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[3]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[4]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[5]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[6]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[7]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[8]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[9]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[10]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[11]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[12]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[13]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[14]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[15]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;


	} else {

		BIG expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[15]) & mask48;
		BIG halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[14]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[13]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[12]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[11]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[10]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[9]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[8]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[7]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[6]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[5]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[4]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[3]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[2]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[1]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;

		expandedRight = blockExpansionPBox32_48(rightHalf);
		expandedRight = (expandedRight ^ keys[0]) & mask48;
		halfBlock = sBoxes48_32(expandedRight);
		halfBlock = straightPBox32_32(halfBlock);
		tempLeftHalf = rightHalf;
		rightHalf = leftHalf ^ halfBlock;
		leftHalf = tempLeftHalf;
	}


	block = finalPermutation(block);

	return block;
};

static BIG straightPBox32_32(BIG halfBlock) {
	BIG one = 1;
	BIG permutedBlock = 0;

	if (halfBlock & (one << 31)) permutedBlock |= (one << (32 - 9));
	if (halfBlock & (one << 30)) permutedBlock |= (one << (32 - 17));
	if (halfBlock & (one << 29)) permutedBlock |= (one << (32 - 23));
	if (halfBlock & (one << 28)) permutedBlock |= (one << (32 - 31));
	if (halfBlock & (one << 27)) permutedBlock |= (one << (32 - 13));
	if (halfBlock & (one << 26)) permutedBlock |= (one << (32 - 28));
	if (halfBlock & (one << 25)) permutedBlock |= (one << (32 - 2));
	if (halfBlock & (one << 24)) permutedBlock |= (one << (32 - 18));
	if (halfBlock & (one << 23)) permutedBlock |= (one << (32 - 24));
	if (halfBlock & (one << 22)) permutedBlock |= (one << (32 - 16));
	if (halfBlock & (one << 21)) permutedBlock |= (one << (32 - 30));
	if (halfBlock & (one << 20)) permutedBlock |= (one << (32 - 6));
	if (halfBlock & (one << 19)) permutedBlock |= (one << (32 - 26));
	if (halfBlock & (one << 18)) permutedBlock |= (one << (32 - 20));
	if (halfBlock & (one << 17)) permutedBlock |= (one << (32 - 10));
	if (halfBlock & (one << 16)) permutedBlock |= (one << (32 - 1));
	if (halfBlock & (one << 15)) permutedBlock |= (one << (32 - 8));
	if (halfBlock & (one << 14)) permutedBlock |= (one << (32 - 14));
	if (halfBlock & (one << 13)) permutedBlock |= (one << (32 - 25));
	if (halfBlock & (one << 12)) permutedBlock |= (one << (32 - 3));
	if (halfBlock & (one << 11)) permutedBlock |= (one << (32 - 4));
	if (halfBlock & (one << 10)) permutedBlock |= (one << (32 - 29));
	if (halfBlock & (one << 9)) permutedBlock |= (one << (32 - 11));
	if (halfBlock & (one << 8)) permutedBlock |= (one << (32 - 19));
	if (halfBlock & (one << 7)) permutedBlock |= (one << (32 - 32));
	if (halfBlock & (one << 6)) permutedBlock |= (one << (32 - 12));
	if (halfBlock & (one << 5)) permutedBlock |= (one << (32 - 22));
	if (halfBlock & (one << 4)) permutedBlock |= (one << (32 - 7));
	if (halfBlock & (one << 3)) permutedBlock |= (one << (32 - 5));
	if (halfBlock & (one << 2)) permutedBlock |= (one << (32 - 27));
	if (halfBlock & (one << 1)) permutedBlock |= (one << (32 - 15));
	if (halfBlock & (one << 0)) permutedBlock |= (one << (32 - 21));

	return permutedBlock;
}

static BIG sBoxes48_32(BIG expandedHalf) {
	BIG mask6 = 0x3f;
	BIG halfBlock = 0;
	halfBlock |= s_box_substitution[0][(expandedHalf >> 42) & mask6];
	halfBlock << 6;
	halfBlock |= s_box_substitution[1][(expandedHalf >> 36) & mask6];
	halfBlock << 6;
	halfBlock |= s_box_substitution[2][(expandedHalf >> 30) & mask6];
	halfBlock << 6;
	halfBlock |= s_box_substitution[3][(expandedHalf >> 24) & mask6];
	halfBlock << 6;
	halfBlock |= s_box_substitution[4][(expandedHalf >> 18) & mask6];
	halfBlock << 6;
	halfBlock |= s_box_substitution[5][(expandedHalf >> 12) & mask6];
	halfBlock << 6;
	halfBlock |= s_box_substitution[6][(expandedHalf >> 6) & mask6];
	halfBlock << 6;
	halfBlock |= s_box_substitution[7][(expandedHalf >> 0) & mask6];
	halfBlock << 6;

	return halfBlock;
}

// the basics of the permutation are commented in KeyGen.cpp.
// please refer to keyPBox64_56 to understand how this aspect works
static BIG initialPermutation(BIG block) {
	BIG one = 1;
	BIG permutedBlock = 0;

	if (block & (one << 63)) permutedBlock |= (one << (64 - 40));
	if (block & (one << 62)) permutedBlock |= (one << (64 - 8));
	if (block & (one << 61)) permutedBlock |= (one << (64 - 48));
	if (block & (one << 60)) permutedBlock |= (one << (64 - 16));
	if (block & (one << 59)) permutedBlock |= (one << (64 - 56));
	if (block & (one << 58)) permutedBlock |= (one << (64 - 24));
	if (block & (one << 57)) permutedBlock |= (one << (64 - 64));
	if (block & (one << 56)) permutedBlock |= (one << (64 - 32));
	if (block & (one << 55)) permutedBlock |= (one << (64 - 39));
	if (block & (one << 54)) permutedBlock |= (one << (64 - 7));
	if (block & (one << 53)) permutedBlock |= (one << (64 - 47));
	if (block & (one << 52)) permutedBlock |= (one << (64 - 15));
	if (block & (one << 51)) permutedBlock |= (one << (64 - 55));
	if (block & (one << 50)) permutedBlock |= (one << (64 - 23));
	if (block & (one << 49)) permutedBlock |= (one << (64 - 63));
	if (block & (one << 48)) permutedBlock |= (one << (64 - 31));

	if (block & (one << 47)) permutedBlock |= (one << (64 - 38));
	if (block & (one << 46)) permutedBlock |= (one << (64 - 6));
	if (block & (one << 45)) permutedBlock |= (one << (64 - 46));
	if (block & (one << 44)) permutedBlock |= (one << (64 - 14));
	if (block & (one << 43)) permutedBlock |= (one << (64 - 54));
	if (block & (one << 42)) permutedBlock |= (one << (64 - 22));
	if (block & (one << 41)) permutedBlock |= (one << (64 - 62));
	if (block & (one << 40)) permutedBlock |= (one << (64 - 30));
	if (block & (one << 39)) permutedBlock |= (one << (64 - 37));
	if (block & (one << 38)) permutedBlock |= (one << (64 - 5));
	if (block & (one << 37)) permutedBlock |= (one << (64 - 45));
	if (block & (one << 36)) permutedBlock |= (one << (64 - 13));
	if (block & (one << 35)) permutedBlock |= (one << (64 - 53));
	if (block & (one << 34)) permutedBlock |= (one << (64 - 21));
	if (block & (one << 33)) permutedBlock |= (one << (64 - 61));
	if (block & (one << 32)) permutedBlock |= (one << (64 - 29));

	if (block & (one << 31)) permutedBlock |= (one << (64 - 36));
	if (block & (one << 30)) permutedBlock |= (one << (64 - 4));
	if (block & (one << 29)) permutedBlock |= (one << (64 - 44));
	if (block & (one << 28)) permutedBlock |= (one << (64 - 12));
	if (block & (one << 27)) permutedBlock |= (one << (64 - 52));
	if (block & (one << 26)) permutedBlock |= (one << (64 - 20));
	if (block & (one << 25)) permutedBlock |= (one << (64 - 60));
	if (block & (one << 24)) permutedBlock |= (one << (64 - 28));
	if (block & (one << 23)) permutedBlock |= (one << (64 - 35));
	if (block & (one << 22)) permutedBlock |= (one << (64 - 3));
	if (block & (one << 21)) permutedBlock |= (one << (64 - 43));
	if (block & (one << 20)) permutedBlock |= (one << (64 - 11));
	if (block & (one << 19)) permutedBlock |= (one << (64 - 51));
	if (block & (one << 18)) permutedBlock |= (one << (64 - 19));
	if (block & (one << 17)) permutedBlock |= (one << (64 - 59));
	if (block & (one << 16)) permutedBlock |= (one << (64 - 27));

	if (block & (one << 15)) permutedBlock |= (one << (64 - 34));
	if (block & (one << 14)) permutedBlock |= (one << (64 - 2));
	if (block & (one << 13)) permutedBlock |= (one << (64 - 42));
	if (block & (one << 12)) permutedBlock |= (one << (64 - 10));
	if (block & (one << 11)) permutedBlock |= (one << (64 - 50));
	if (block & (one << 10)) permutedBlock |= (one << (64 - 18));
	if (block & (one << 9)) permutedBlock |= (one << (64 - 58));
	if (block & (one << 8)) permutedBlock |= (one << (64 - 26));
	if (block & (one << 7)) permutedBlock |= (one << (64 - 33));
	if (block & (one << 6)) permutedBlock |= (one << (64 - 1));
	if (block & (one << 5)) permutedBlock |= (one << (64 - 41));
	if (block & (one << 4)) permutedBlock |= (one << (64 - 9));
	if (block & (one << 3)) permutedBlock |= (one << (64 - 49));
	if (block & (one << 2)) permutedBlock |= (one << (64 - 17));
	if (block & (one << 1)) permutedBlock |= (one << (64 - 57));
	if (block & (one << 0)) permutedBlock |= (one << (64 - 25));

	return permutedBlock;
}

// the expansion p box increases the size of the 32 bit input block to 48 to match the size 
// of the keys for each round. this works by sending some of the input to two outputs.
static BIG blockExpansionPBox32_48(BIG block) {
	BIG one = 1;
	BIG permutedBlock = 0;

	if (block & (one << 31)) permutedBlock |= (one << (48 - 2));
	if (block & (one << 31)) permutedBlock |= (one << (48 - 48));
	if (block & (one << 30)) permutedBlock |= (one << (48 - 3));
	if (block & (one << 29)) permutedBlock |= (one << (48 - 4));
	if (block & (one << 28)) permutedBlock |= (one << (48 - 5));
	if (block & (one << 28)) permutedBlock |= (one << (48 - 7));
	if (block & (one << 27)) permutedBlock |= (one << (48 - 6));
	if (block & (one << 27)) permutedBlock |= (one << (48 - 8));
	if (block & (one << 26)) permutedBlock |= (one << (48 - 9));
	if (block & (one << 25)) permutedBlock |= (one << (48 - 10));
	if (block & (one << 24)) permutedBlock |= (one << (48 - 11));
	if (block & (one << 24)) permutedBlock |= (one << (48 - 13));
	if (block & (one << 23)) permutedBlock |= (one << (48 - 12));
	if (block & (one << 23)) permutedBlock |= (one << (48 - 14));
	if (block & (one << 22)) permutedBlock |= (one << (48 - 15));
	if (block & (one << 21)) permutedBlock |= (one << (48 - 16));
	if (block & (one << 20)) permutedBlock |= (one << (48 - 17));
	if (block & (one << 20)) permutedBlock |= (one << (48 - 19));
	if (block & (one << 19)) permutedBlock |= (one << (48 - 18));
	if (block & (one << 19)) permutedBlock |= (one << (48 - 20));
	if (block & (one << 18)) permutedBlock |= (one << (48 - 21));
	if (block & (one << 17)) permutedBlock |= (one << (48 - 22));
	if (block & (one << 16)) permutedBlock |= (one << (48 - 23));
	if (block & (one << 16)) permutedBlock |= (one << (48 - 25));

	if (block & (one << 15)) permutedBlock |= (one << (48 - 24));
	if (block & (one << 15)) permutedBlock |= (one << (48 - 26));
	if (block & (one << 14)) permutedBlock |= (one << (48 - 27));
	if (block & (one << 13)) permutedBlock |= (one << (48 - 28));
	if (block & (one << 12)) permutedBlock |= (one << (48 - 29));
	if (block & (one << 12)) permutedBlock |= (one << (48 - 31));
	if (block & (one << 11)) permutedBlock |= (one << (48 - 30));
	if (block & (one << 11)) permutedBlock |= (one << (48 - 32));
	if (block & (one << 10)) permutedBlock |= (one << (48 - 33));
	if (block & (one << 9)) permutedBlock |= (one << (48 - 34));
	if (block & (one << 8)) permutedBlock |= (one << (48 - 35));
	if (block & (one << 8)) permutedBlock |= (one << (48 - 37));
	if (block & (one << 7)) permutedBlock |= (one << (48 - 36));
	if (block & (one << 7)) permutedBlock |= (one << (48 - 38));
	if (block & (one << 6)) permutedBlock |= (one << (48 - 39));
	if (block & (one << 5)) permutedBlock |= (one << (48 - 40));
	if (block & (one << 4)) permutedBlock |= (one << (48 - 41));
	if (block & (one << 4)) permutedBlock |= (one << (48 - 43));
	if (block & (one << 3)) permutedBlock |= (one << (48 - 42));
	if (block & (one << 3)) permutedBlock |= (one << (48 - 44));
	if (block & (one << 2)) permutedBlock |= (one << (48 - 45));
	if (block & (one << 1)) permutedBlock |= (one << (48 - 46));
	if (block & (one << 0)) permutedBlock |= (one << (48 - 47));
	if (block & (one << 0)) permutedBlock |= (one << (48 - 1));

	return permutedBlock;
}

// the basics of the permutation are commented in KeyGen.cpp.
// please refer to keyPBox64_56 to understand how this aspect works
static BIG finalPermutation(BIG block) {
	BIG one = 1;
	BIG permutedBlock = 0;

	if (block & (one << 63)) permutedBlock |= (one << (64 - 58));
	if (block & (one << 62)) permutedBlock |= (one << (64 - 50));
	if (block & (one << 61)) permutedBlock |= (one << (64 - 42));
	if (block & (one << 60)) permutedBlock |= (one << (64 - 34));
	if (block & (one << 59)) permutedBlock |= (one << (64 - 26));
	if (block & (one << 58)) permutedBlock |= (one << (64 - 18));
	if (block & (one << 57)) permutedBlock |= (one << (64 - 10));
	if (block & (one << 56)) permutedBlock |= (one << (64 - 2));
	if (block & (one << 55)) permutedBlock |= (one << (64 - 60));
	if (block & (one << 54)) permutedBlock |= (one << (64 - 52));
	if (block & (one << 53)) permutedBlock |= (one << (64 - 44));
	if (block & (one << 52)) permutedBlock |= (one << (64 - 36));
	if (block & (one << 51)) permutedBlock |= (one << (64 - 28));
	if (block & (one << 50)) permutedBlock |= (one << (64 - 20));
	if (block & (one << 49)) permutedBlock |= (one << (64 - 12));
	if (block & (one << 48)) permutedBlock |= (one << (64 - 4));

	if (block & (one << 47)) permutedBlock |= (one << (64 - 62));
	if (block & (one << 46)) permutedBlock |= (one << (64 - 54));
	if (block & (one << 45)) permutedBlock |= (one << (64 - 46));
	if (block & (one << 44)) permutedBlock |= (one << (64 - 38));
	if (block & (one << 43)) permutedBlock |= (one << (64 - 30));
	if (block & (one << 42)) permutedBlock |= (one << (64 - 22));
	if (block & (one << 41)) permutedBlock |= (one << (64 - 14));
	if (block & (one << 40)) permutedBlock |= (one << (64 - 6));
	if (block & (one << 39)) permutedBlock |= (one << (64 - 64));
	if (block & (one << 38)) permutedBlock |= (one << (64 - 56));
	if (block & (one << 37)) permutedBlock |= (one << (64 - 48));
	if (block & (one << 36)) permutedBlock |= (one << (64 - 40));
	if (block & (one << 35)) permutedBlock |= (one << (64 - 32));
	if (block & (one << 34)) permutedBlock |= (one << (64 - 24));
	if (block & (one << 33)) permutedBlock |= (one << (64 - 16));
	if (block & (one << 32)) permutedBlock |= (one << (64 - 8));

	if (block & (one << 31)) permutedBlock |= (one << (64 - 57));
	if (block & (one << 30)) permutedBlock |= (one << (64 - 49));
	if (block & (one << 29)) permutedBlock |= (one << (64 - 41));
	if (block & (one << 28)) permutedBlock |= (one << (64 - 33));
	if (block & (one << 27)) permutedBlock |= (one << (64 - 25));
	if (block & (one << 26)) permutedBlock |= (one << (64 - 17));
	if (block & (one << 25)) permutedBlock |= (one << (64 - 9));
	if (block & (one << 24)) permutedBlock |= (one << (64 - 1));
	if (block & (one << 23)) permutedBlock |= (one << (64 - 59));
	if (block & (one << 22)) permutedBlock |= (one << (64 - 51));
	if (block & (one << 21)) permutedBlock |= (one << (64 - 43));
	if (block & (one << 20)) permutedBlock |= (one << (64 - 35));
	if (block & (one << 19)) permutedBlock |= (one << (64 - 27));
	if (block & (one << 18)) permutedBlock |= (one << (64 - 19));
	if (block & (one << 17)) permutedBlock |= (one << (64 - 11));
	if (block & (one << 16)) permutedBlock |= (one << (64 - 3));

	if (block & (one << 15)) permutedBlock |= (one << (64 - 61));
	if (block & (one << 14)) permutedBlock |= (one << (64 - 53));
	if (block & (one << 13)) permutedBlock |= (one << (64 - 45));
	if (block & (one << 12)) permutedBlock |= (one << (64 - 37));
	if (block & (one << 11)) permutedBlock |= (one << (64 - 29));
	if (block & (one << 10)) permutedBlock |= (one << (64 - 21));
	if (block & (one << 9)) permutedBlock |= (one << (64 - 13));
	if (block & (one << 8)) permutedBlock |= (one << (64 - 5));
	if (block & (one << 7)) permutedBlock |= (one << (64 - 63));
	if (block & (one << 6)) permutedBlock |= (one << (64 - 55));
	if (block & (one << 5)) permutedBlock |= (one << (64 - 47));
	if (block & (one << 4)) permutedBlock |= (one << (64 - 39));
	if (block & (one << 3)) permutedBlock |= (one << (64 - 31));
	if (block & (one << 2)) permutedBlock |= (one << (64 - 23));
	if (block & (one << 1)) permutedBlock |= (one << (64 - 15));
	if (block & (one << 0)) permutedBlock |= (one << (64 - 7));

	return permutedBlock;
}
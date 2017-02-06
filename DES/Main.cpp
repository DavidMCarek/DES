#include <iostream>
#include <fstream>
#include "KeyGen.h"
#include "Macros.h"
#include "Utils.h"

using namespace std;

BIG initialPermutation(BIG text);
BIG initialPermutation(BIG text);

int main(int argc, char *argv[]) {
	// make sure we have input in the form 
	// DES <-action> <key> <mode> <infile> <outfile>

	// this can be accomplished by checking the number of arguments
	if (argc != 6) {
		cout << "Invalid arguments. DES <-action> <key> <mode> <infile> <outfile>" << endl;
		return 1;
	}

	// next we make sure that the action selected is valid
	bool encrypting;
	if (_stricmp(argv[1], "-d") == 0) 
		encrypting = false;
	else if (_stricmp(argv[1], "-e") == 0)
		encrypting = true;
	else {
		cout << "Invalid action selected. Use -e or -d for encrypting/decrypting." << endl;
		return 1;
	}

	BIG key = 0;

	// then we check to see if the key is 16 hex characters or 8 characters
	// if the keys are valid we need to convert them to unsigned long longs (BIG) which can hold 64 bits
	int keyLength = strlen(argv[2]);

	cout << "Key " << argv[2] << endl;

	if (keyLength == 16 &&
		isxdigit(argv[2][0]) &&
		isxdigit(argv[2][1]) &&
		isxdigit(argv[2][2]) &&
		isxdigit(argv[2][3]) &&
		isxdigit(argv[2][4]) &&
		isxdigit(argv[2][5]) &&
		isxdigit(argv[2][6]) &&
		isxdigit(argv[2][7]) &&
		isxdigit(argv[2][8]) &&
		isxdigit(argv[2][9]) &&
		isxdigit(argv[2][10]) &&
		isxdigit(argv[2][11]) &&
		isxdigit(argv[2][12]) &&
		isxdigit(argv[2][13]) &&
		isxdigit(argv[2][14]) &&
		isxdigit(argv[2][15])) {

		// the hex key can use the function below to be converted into a BIG
		key = strtoull(argv[2], NULL, 16);
	} else if (keyLength == 10 &&
		argv[2][0] == '\'' &&
		argv[2][9] == '\'') {
		// this conversion is a bit more confusing. we take a character's bits, cast them as a big, 
		// and shift them to the correct bit locations of the key. Then that value is ORed with the
		// current key until the whole key has been converted.
		key |= ((BIG)argv[2][1] << 56);
		key |= ((BIG)argv[2][2] << 48); 
		key |= ((BIG)argv[2][3] << 40); 
		key |= ((BIG)argv[2][4] << 32); 
		key |= ((BIG)argv[2][5] << 24);
		key |= ((BIG)argv[2][6] << 16);
		key |= ((BIG)argv[2][7] << 8);
		key |= ((BIG)argv[2][8]);

	} else if (keyLength == 8) {
		// since windows does not require the single ticks around the parameter i added this in just in case
		key |= ((BIG)argv[2][0] << 56);
		key |= ((BIG)argv[2][1] << 48);
		key |= ((BIG)argv[2][2] << 40);
		key |= ((BIG)argv[2][3] << 32);
		key |= ((BIG)argv[2][4] << 24);
		key |= ((BIG)argv[2][5] << 16);
		key |= ((BIG)argv[2][6] << 8);
		key |= ((BIG)argv[2][7]);

	} else {
		cout << "Invalid key. Must be 16 digit hex or 8 characters." << endl;
		return 1;
	}

	// now we need to check that the mode is ecb or cbc
	bool isCBC;
	if (_stricmp(argv[3], "cbc") == 0)
		isCBC = true;
	else if (_stricmp(argv[3], "ecb") == 0)
		isCBC = false;
	else {
		cout << "Invalid mode selected. Use cbc or ecb." << endl;
		return 1;
	}

	ifstream inputStream;
	inputStream.open(argv[4], std::ios::binary);

	// if we couldn't open the file, let the user know and return
	if (inputStream.fail()) {
		cout << "Could not open input file" << std::endl;
		return 1;
	}

	inputStream.seekg(0, inputStream.end);
	BIG length = inputStream.tellg();
	inputStream.seekg(0, inputStream.beg);

	// now that we have gotten this far we know that all inputs have been verified and now we can move
	// on to the key generation for each of the 16 rounds
	BIG * keyList = generateKeys(key);

	return 0;
}

// the basics of the permutation are commented in KeyGen.cpp.
// please refer to keyPBox64_56 to understand how this aspect works
BIG initialPermutation(BIG text) {
	BIG one = 1;
	BIG permutedText = 0;

	if (text & (one << 63)) permutedText |= (one << (64 - 40));
	if (text & (one << 62)) permutedText |= (one << (64 - 8));
	if (text & (one << 61)) permutedText |= (one << (64 - 48));
	if (text & (one << 60)) permutedText |= (one << (64 - 16));
	if (text & (one << 59)) permutedText |= (one << (64 - 56));
	if (text & (one << 58)) permutedText |= (one << (64 - 24));
	if (text & (one << 57)) permutedText |= (one << (64 - 64));
	if (text & (one << 56)) permutedText |= (one << (64 - 32));
	if (text & (one << 55)) permutedText |= (one << (64 - 39));
	if (text & (one << 54)) permutedText |= (one << (64 - 7));
	if (text & (one << 53)) permutedText |= (one << (64 - 47));
	if (text & (one << 52)) permutedText |= (one << (64 - 15));
	if (text & (one << 51)) permutedText |= (one << (64 - 55));
	if (text & (one << 50)) permutedText |= (one << (64 - 23));
	if (text & (one << 49)) permutedText |= (one << (64 - 63));
	if (text & (one << 48)) permutedText |= (one << (64 - 31));

	if (text & (one << 47)) permutedText |= (one << (64 - 38));
	if (text & (one << 46)) permutedText |= (one << (64 - 6));
	if (text & (one << 45)) permutedText |= (one << (64 - 46));
	if (text & (one << 44)) permutedText |= (one << (64 - 14));
	if (text & (one << 43)) permutedText |= (one << (64 - 54));
	if (text & (one << 42)) permutedText |= (one << (64 - 22));
	if (text & (one << 41)) permutedText |= (one << (64 - 62));
	if (text & (one << 40)) permutedText |= (one << (64 - 30));
	if (text & (one << 39)) permutedText |= (one << (64 - 37));
	if (text & (one << 38)) permutedText |= (one << (64 - 5));
	if (text & (one << 37)) permutedText |= (one << (64 - 45));
	if (text & (one << 36)) permutedText |= (one << (64 - 13));
	if (text & (one << 35)) permutedText |= (one << (64 - 53));
	if (text & (one << 34)) permutedText |= (one << (64 - 21));
	if (text & (one << 33)) permutedText |= (one << (64 - 61));
	if (text & (one << 32)) permutedText |= (one << (64 - 29));

	if (text & (one << 31)) permutedText |= (one << (64 - 36));
	if (text & (one << 30)) permutedText |= (one << (64 - 4));
	if (text & (one << 29)) permutedText |= (one << (64 - 44));
	if (text & (one << 28)) permutedText |= (one << (64 - 12));
	if (text & (one << 27)) permutedText |= (one << (64 - 52));
	if (text & (one << 26)) permutedText |= (one << (64 - 20));
	if (text & (one << 25)) permutedText |= (one << (64 - 60));
	if (text & (one << 24)) permutedText |= (one << (64 - 28));
	if (text & (one << 23)) permutedText |= (one << (64 - 35));
	if (text & (one << 22)) permutedText |= (one << (64 - 3));
	if (text & (one << 21)) permutedText |= (one << (64 - 43));
	if (text & (one << 20)) permutedText |= (one << (64 - 11));
	if (text & (one << 19)) permutedText |= (one << (64 - 51));
	if (text & (one << 18)) permutedText |= (one << (64 - 19));
	if (text & (one << 17)) permutedText |= (one << (64 - 59));
	if (text & (one << 16)) permutedText |= (one << (64 - 27));

	if (text & (one << 15)) permutedText |= (one << (64 - 34));
	if (text & (one << 14)) permutedText |= (one << (64 - 2));
	if (text & (one << 13)) permutedText |= (one << (64 - 42));
	if (text & (one << 12)) permutedText |= (one << (64 - 10));
	if (text & (one << 11)) permutedText |= (one << (64 - 50));
	if (text & (one << 10)) permutedText |= (one << (64 - 18));
	if (text & (one << 9)) permutedText |= (one << (64 - 58));
	if (text & (one << 8)) permutedText |= (one << (64 - 26));
	if (text & (one << 7)) permutedText |= (one << (64 - 33));
	if (text & (one << 6)) permutedText |= (one << (64 - 1));
	if (text & (one << 5)) permutedText |= (one << (64 - 41));
	if (text & (one << 4)) permutedText |= (one << (64 - 9));
	if (text & (one << 3)) permutedText |= (one << (64 - 49));
	if (text & (one << 2)) permutedText |= (one << (64 - 17));
	if (text & (one << 1)) permutedText |= (one << (64 - 57));
	if (text & (one << 0)) permutedText |= (one << (64 - 25));

	return permutedText;
}

// the basics of the permutation are commented in KeyGen.cpp.
// please refer to keyPBox64_56 to understand how this aspect works
BIG finalPermutation(BIG text) {
	BIG one = 1;
	BIG permutedText = 0;

	if (text & (one << 63)) permutedText |= (one << (64 - 58));
	if (text & (one << 62)) permutedText |= (one << (64 - 50));
	if (text & (one << 61)) permutedText |= (one << (64 - 42));
	if (text & (one << 60)) permutedText |= (one << (64 - 34));
	if (text & (one << 59)) permutedText |= (one << (64 - 26));
	if (text & (one << 58)) permutedText |= (one << (64 - 18));
	if (text & (one << 57)) permutedText |= (one << (64 - 10));
	if (text & (one << 56)) permutedText |= (one << (64 - 2));
	if (text & (one << 55)) permutedText |= (one << (64 - 60));
	if (text & (one << 54)) permutedText |= (one << (64 - 52));
	if (text & (one << 53)) permutedText |= (one << (64 - 44));
	if (text & (one << 52)) permutedText |= (one << (64 - 36));
	if (text & (one << 51)) permutedText |= (one << (64 - 28));
	if (text & (one << 50)) permutedText |= (one << (64 - 20));
	if (text & (one << 49)) permutedText |= (one << (64 - 12));
	if (text & (one << 48)) permutedText |= (one << (64 - 4));

	if (text & (one << 47)) permutedText |= (one << (64 - 62));
	if (text & (one << 46)) permutedText |= (one << (64 - 54));
	if (text & (one << 45)) permutedText |= (one << (64 - 46));
	if (text & (one << 44)) permutedText |= (one << (64 - 38));
	if (text & (one << 43)) permutedText |= (one << (64 - 30));
	if (text & (one << 42)) permutedText |= (one << (64 - 22));
	if (text & (one << 41)) permutedText |= (one << (64 - 14));
	if (text & (one << 40)) permutedText |= (one << (64 - 6));
	if (text & (one << 39)) permutedText |= (one << (64 - 64));
	if (text & (one << 38)) permutedText |= (one << (64 - 56));
	if (text & (one << 37)) permutedText |= (one << (64 - 48));
	if (text & (one << 36)) permutedText |= (one << (64 - 40));
	if (text & (one << 35)) permutedText |= (one << (64 - 32));
	if (text & (one << 34)) permutedText |= (one << (64 - 24));
	if (text & (one << 33)) permutedText |= (one << (64 - 16));
	if (text & (one << 32)) permutedText |= (one << (64 - 8));

	if (text & (one << 31)) permutedText |= (one << (64 - 57));
	if (text & (one << 30)) permutedText |= (one << (64 - 49));
	if (text & (one << 29)) permutedText |= (one << (64 - 41));
	if (text & (one << 28)) permutedText |= (one << (64 - 33));
	if (text & (one << 27)) permutedText |= (one << (64 - 25));
	if (text & (one << 26)) permutedText |= (one << (64 - 17));
	if (text & (one << 25)) permutedText |= (one << (64 - 9));
	if (text & (one << 24)) permutedText |= (one << (64 - 1));
	if (text & (one << 23)) permutedText |= (one << (64 - 59));
	if (text & (one << 22)) permutedText |= (one << (64 - 51));
	if (text & (one << 21)) permutedText |= (one << (64 - 43));
	if (text & (one << 20)) permutedText |= (one << (64 - 35));
	if (text & (one << 19)) permutedText |= (one << (64 - 27));
	if (text & (one << 18)) permutedText |= (one << (64 - 19));
	if (text & (one << 17)) permutedText |= (one << (64 - 11));
	if (text & (one << 16)) permutedText |= (one << (64 - 3));

	if (text & (one << 15)) permutedText |= (one << (64 - 61));
	if (text & (one << 14)) permutedText |= (one << (64 - 53));
	if (text & (one << 13)) permutedText |= (one << (64 - 45));
	if (text & (one << 12)) permutedText |= (one << (64 - 37));
	if (text & (one << 11)) permutedText |= (one << (64 - 29));
	if (text & (one << 10)) permutedText |= (one << (64 - 21));
	if (text & (one << 9)) permutedText |= (one << (64 - 13));
	if (text & (one << 8)) permutedText |= (one << (64 - 5));
	if (text & (one << 7)) permutedText |= (one << (64 - 63));
	if (text & (one << 6)) permutedText |= (one << (64 - 55));
	if (text & (one << 5)) permutedText |= (one << (64 - 47));
	if (text & (one << 4)) permutedText |= (one << (64 - 39));
	if (text & (one << 3)) permutedText |= (one << (64 - 31));
	if (text & (one << 2)) permutedText |= (one << (64 - 23));
	if (text & (one << 1)) permutedText |= (one << (64 - 15));
	if (text & (one << 0)) permutedText |= (one << (64 - 7));

	return permutedText;
}
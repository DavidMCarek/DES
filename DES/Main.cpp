#include <iostream>
#include <fstream>
#include "KeyGen.h"
#include "Macros.h"
#include "Utils.h"

using namespace std;

int main(int argc, char *argv[]) {
	// make sure we have input in the form 
	// DES <–action> <key> <mode> <infile> <outfile>

	// this can be accomplished by checking the number of arguments
	if (argc != 6) 
	{
		cout << "Invalid arguments." << endl;
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
		isxdigit(argv[2][15])) 
	{
		// the hex key can use the function below to be converted into a BIG
		key = strtoull(argv[2], NULL, 16);
	}
	else if (keyLength == 10 &&
		argv[2][0] == '\'' &&
		argv[2][9] == '\'') 
	{
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
	}
	else if (keyLength == 8) {
		// since windows does not require the single ticks around the parameter i added this in just in case
		key |= ((BIG)argv[2][0] << 56);
		key |= ((BIG)argv[2][1] << 48);
		key |= ((BIG)argv[2][2] << 40);
		key |= ((BIG)argv[2][3] << 32);
		key |= ((BIG)argv[2][4] << 24);
		key |= ((BIG)argv[2][5] << 16);
		key |= ((BIG)argv[2][6] << 8);
		key |= ((BIG)argv[2][7]);
	}
	else {
		cout << "Invalid key. Must be 16 digit hex or 8 characters." << endl;
		return 1;
	}

	printBits(sizeof(key), &key);


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
		//return 1;
	}

	// now that we have gotten this far we know that all inputs have been verified and now we can move
	// on to the key generation for each of the 16 rounds
	BIG * keyList = generateKeys(key);



	return 0;
}

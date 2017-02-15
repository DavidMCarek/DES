// EECS 4980:805 Inside Cryptography
// DES Project
// David Carek

// This file is the main control for running DES. It reads and validates input parameters, reads from the input file, 
// calls the run DES function, and writes to the output file.

#include <iostream>
#include <fstream>
#include <string>

#include "KeyGen.h"
#include "Macros.h"
#include "Utils.h"
#include "DES.h"
using namespace std;

static BIG garbageGenerator(int bytesRequired);

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
	}
	else if (keyLength == 10 &&
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

	// now we need to check that the mode is ecb or cbc
	bool isCBC;
	if (_stricmp(argv[3], "cbc") == 0) {
		isCBC = true;
		cout << "Sorry this functionality is not available yet." << endl;
		return 1;
	}
	else if (_stricmp(argv[3], "ecb") == 0)
		isCBC = false;
	else {
		cout << "Invalid mode selected. Use cbc or ecb." << endl;
		return 1;
	}

	ifstream inputStream;
	inputStream.open(argv[4], std::ios::binary);

	// this next little section is for encrypting bitmaps. i thought it would be interesting to see 
	// how an encrypted image turns out. so for our purposes we dont care about its decryption so
	// wont implement that functionality. also i suspect that cbc will provide a very different 
	// looking image. first we find the end of the string so we can check the last 4 characters. this 
	// will make sure that the file extension is '.bmp'
	bool endOfString = false;
	int strLoc = 0;
	while (!endOfString) {
		if (argv[4][strLoc] == '\0')
			endOfString = true;
		else
			strLoc++;
	}
	// if we read in a bmp we need to ignore the first 14 bytes which are the header
	bool isBMP = false;
	if (argv[4][strLoc - 4] == '.' &&
		argv[4][strLoc - 3] == 'b' &&
		argv[4][strLoc - 2] == 'm' &&
		argv[4][strLoc - 1] == 'p')
		isBMP = true;


	// if we couldn't open the file, let the user know and return
	if (inputStream.fail()) {
		cout << "Could not open input file" << endl;
		return 1;
	}

	// since the file is valid we find its length
	inputStream.seekg(0, inputStream.end);
	unsigned int length = inputStream.tellg();
	inputStream.seekg(0, inputStream.beg);

	// then we make sure we can open the output file
	ofstream outputStream;
	outputStream.open(argv[5], std::ios::binary);
	if (outputStream.fail()) {
		cout << "Could not open output file" << endl;
		return 1;
	}

	// now that we have gotten this far we know that all inputs have been verified and now we can move
	// on to the key generation for each of the 16 rounds
	BIG * keyList = new BIG[16];
	generateKeys(key, keyList);

	// we will need a buffer to read in 8 bytes of the file at a time.
	char * buffer = new char[8];

	// if we're encrypting we will need to generate garbage for the left half of the first block and
	// the length of the file will be located in the right half of that block
	if (encrypting) {
		BIG block;
		// if we are encrypting a bitmap we need to leave the first 14 bytes alone because those
		// are the header bytes
		if (isBMP) {
			char * bmpBuffer = new char[54];
			inputStream.read(bmpBuffer, 54);
			outputStream.write(bmpBuffer, 54);
			length -= 54;
		}
		else {
			block = garbageGenerator(4);
			block = block << 32;
			block |= length;

			// now that we have generated the first block we need to run des on it and then perform an
			// endian swap before we write the value to the file since just casting the block leaves them
			// in reverse order.
			block = runDES(keyList, block, encrypting);
			block = _byteswap_uint64(block);
			outputStream.write((const char *)&block, 8);
		}

		// now we will run DES on all of the remaining blocks in the file until we reach the last
		// potential block. I say potential because once we have fewer than 8 bytes left, either the
		// file is exactly a multiple of 8 bytes long and we're done, or there are 1-7 bytes left
		// that require some padding to be encrypted. we also run into the endian issue here again
		while (length > 7) {
			inputStream.read(buffer, 8);
			length -= 8;
			block = _byteswap_uint64(*(BIG*)buffer);
			block = runDES(keyList, block, encrypting);
			block = _byteswap_uint64(block);
			outputStream.write((const char *)&block, 8);
		}

		// if the length is non zero here then we need some garbage bytes for padding at the end
		// of the file. we can just fill each byte left over in the buffer with garbage to get
		// the padding required
		if (length != 0) {
			inputStream.read(buffer, length);

			do {
				buffer[length] = garbageGenerator(1);
				length++;
			} while (length < 8);

			// now that the padding has been inserted we just run DES and write the output once the
			// needed endian swap is performed
			block = _byteswap_uint64(*(BIG*)buffer);
			block = runDES(keyList, block, encrypting);
			block = _byteswap_uint64(block);
			outputStream.write((const char *)&block, 8);
		}
		
		

	} else {
		// if we reach this section then we are decrypting an encrypted file. we can find the
		// actual length of the file by decrypting the first block and reading the value in the
		// right half of the block. we need to know this value because we have added 8-15 bytes
		// of padding to the encrypted file.
		int actualLength = 0;
		inputStream.read(buffer, 8);
		BIG block = _byteswap_uint64(*(BIG*)buffer);
		block = runDES(keyList, block, encrypting);
		block &= 0xffffffff;
		actualLength = block;

		// this step here is more of a debugging step than anything but it also stops the program
		// from getting stuck decrypting if the file lacks the required size field. since we added
		// those 8-15 padding bits the length of the file should be within that range. if it is not
		// the program lets the user know and then ends
		if (!(length - actualLength < 16 && length - actualLength > 7)) {
			cout << "Size encryption error." << endl;
			return 1;
		}

		// once we get here we know that we have a valid file and can start decrypting each block of
		// the input file. this works the same as the encrpting except the boolean that we pass in
		// is false rather than true
		while (actualLength > 7) {
			inputStream.read(buffer, 8);
			actualLength -= 8;
			BIG block = _byteswap_uint64(*(BIG*)buffer);
			block = runDES(keyList, block, encrypting);
			block = _byteswap_uint64(block);
			outputStream.write((const char *)&block, 8);
		}

		// if we still have bytes left to decrypt it will be 7 or less. by only writing up to the
		// actual length any extra garbage is chopoped off
		if (actualLength != 0) {
			inputStream.read(buffer, 8);
			block = _byteswap_uint64(*(BIG*)buffer);
			block = runDES(keyList, block, encrypting);
			block = _byteswap_uint64(block);
			outputStream.write((const char *)&block, actualLength);
		}
		
	}

	delete keyList;
	delete buffer;
	inputStream.close();
	outputStream.close();

	return 0;
}

// this will be used to create padding for the encrypting section
static BIG garbageGenerator(int bytesRequired) {

	BIG garbage = 0;

	// this section generates a byte of garbage and ORs it with the 64 bit value.
	// then if we need another byte we shift the garbage one byte left to make
	// room for the next byte coming in
	while (bytesRequired > 0) {
		garbage = garbage << 8;
		garbage |= rand() % 256;
		bytesRequired--;
	}

	return garbage;
}
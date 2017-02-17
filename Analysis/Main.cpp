// EECS 4980:805 Inside Cryptography
// DES Analysis Project
// David Carek

#include <iostream>
#include <fstream>
#include <unordered_map>
#include "Main.h"

#define BIG unsigned long long
using namespace std;

// The values below are used for the pop count function 
const BIG m1 = 0x5555555555555555;
const BIG m2 = 0x3333333333333333;
const BIG m4 = 0x0f0f0f0f0f0f0f0f;

static int popcount64(BIG block);

// These arrays are used for getting the frquency counts for different orders
// and sizes of bytes.
static int byteFrequencies[256] = { 0 };
static int digramFrequencies[65536] = { 0 };
static int trigramFrequencies[16777216] = { 0 };

// this program should analyze an encryted and decrypted version of the
// shakespeare file. it needs to create a count of single bits (0 and 1)
// in both files. it also should analyze single byte frequencies. di-gram
// freqeuncies will also need to be counted by creating an array (65536 ints)
// this list will contain all 2 byte combinations in the file. the same will
// be done with tri-grams except the array will be 16777216 elements. For the
// octet frequencies we can use a hash map to speed up increments instead of 
// an array.
int main(int argc, char* argv[]) {
	
	// input: Analaysis <infile>

	// first we have to set up the input stream. this contains the file for the analysis
	ifstream inputStream;
	inputStream.open(argv[1], std::ios::binary);

	// if we couldn't open the file, let the user know and return
	if (inputStream.fail()) {
		cout << "Could not open input file" << endl;
		return 1;
	}

	// for our algorithm to work correctly we need to get the file length
	inputStream.seekg(0, inputStream.end);
	BIG fileLength = inputStream.tellg();
	inputStream.seekg(0, inputStream.beg);

	// then we need to keep a copy of the original length of the file to calculate
	// the number of low bits (0s) in the file.
	BIG originalLength = fileLength;
	BIG onBits = 0; // keeps track of all 1 bits in the file
	char * buffer = new char[8]; // used to read in the input text
	BIG block = 0; // holds the current 8 bytes of the file
	BIG previousBlock; // holds previous 8 bytes of the file
	bool previousBlockInitialized = false;
	BIG mask8 = 0xff; // used for byte
	BIG mask16 = 0xffff; // used for digram
	BIG mask24 = 0xffffff; // used for trigram
	

	unordered_map<BIG, int> octetMap;

	// if our file length is greater than 7 then we have a full block that can be initialized.
	// since this is the first block we will use previous block for our current block. this way
	// previous block is all set for the loop coming up. 
	if (fileLength > 7) {
		// first we read in the 8 byte block and convert it to an unsigned long long.
		inputStream.read(buffer, 8);
		fileLength -= 8;
		previousBlock = _byteswap_uint64(*(BIG*)buffer);
		bool previousBlockInitialized = true;

		// we can keep track of the 1 bits by calculating the popcount or hamming weight of the
		// block. this technique is used whenever we need to add to our bit count
		onBits += popcount64(previousBlock);

		// we can shift the byte we want to look at into the first 8 bits and then isolate those
		// bits with a mask to access that byte's location in the array that contains its count. 
		// the bytes location in the array is then incremented
		byteFrequencies[(previousBlock >> (7 * 8)) & mask8]++;
		byteFrequencies[(previousBlock >> (6 * 8)) & mask8]++;
		byteFrequencies[(previousBlock >> (5 * 8)) & mask8]++;
		byteFrequencies[(previousBlock >> (4 * 8)) & mask8]++;
		byteFrequencies[(previousBlock >> (3 * 8)) & mask8]++;
		byteFrequencies[(previousBlock >> (2 * 8)) & mask8]++;
		byteFrequencies[(previousBlock >> (1 * 8)) & mask8]++;
		byteFrequencies[(previousBlock) & mask8]++;

		// the digram works the same as the bytes only now we look at 16 bits to find the location
		// in the array for the digram's count
		digramFrequencies[(previousBlock >> (6 * 8)) & mask16]++;
		digramFrequencies[(previousBlock >> (5 * 8)) & mask16]++;
		digramFrequencies[(previousBlock >> (4 * 8)) & mask16]++;
		digramFrequencies[(previousBlock >> (3 * 8)) & mask16]++;
		digramFrequencies[(previousBlock >> (2 * 8)) & mask16]++;
		digramFrequencies[(previousBlock >> (1 * 8)) & mask16]++;
		digramFrequencies[(previousBlock) & mask16]++;

		// again the trigram works the same but now we look at 24 bits
		trigramFrequencies[(previousBlock >> (5 * 8)) & mask24]++;
		trigramFrequencies[(previousBlock >> (4 * 8)) & mask24]++;
		trigramFrequencies[(previousBlock >> (3 * 8)) & mask24]++;
		trigramFrequencies[(previousBlock >> (2 * 8)) & mask24]++;
		trigramFrequencies[(previousBlock >> (1 * 8)) & mask24]++;
		trigramFrequencies[(previousBlock) & mask24]++;

		// finally we insert the block into the octet map. we don't have to check if the block
		// exists here since it is the first block.
		octetMap.insert(pair<BIG, int>(previousBlock, 1));
	}

	// now we are on the second block of input. things get a little tricky here since digrams 
	// and trigrams will occupy both the previous block and the current block. it helps to imagine
	// this like looking through a window of size 2 or 3 bytes and the blocks are a tape with
	// characters on it. as the tape goes by and we get to bits 16 and 17 (1 indexed) bit 16 is 
	// part of the previous block and bit 17 the current block but they still make a digram that
	// needs to be counted
	while (fileLength > 7) {
		// this part works the same as above
		inputStream.read(buffer, 8);
		fileLength -= 8;
		block = _byteswap_uint64(*(BIG*)buffer);
		onBits += popcount64(block);
		
		byteFrequencies[(block >> (7 * 8)) & mask8]++;
		byteFrequencies[(block >> (6 * 8)) & mask8]++;
		byteFrequencies[(block >> (5 * 8)) & mask8]++;
		byteFrequencies[(block >> (4 * 8)) & mask8]++;
		byteFrequencies[(block >> (3 * 8)) & mask8]++;
		byteFrequencies[(block >> (2 * 8)) & mask8]++;
		byteFrequencies[(block >> (1 * 8)) & mask8]++;
		byteFrequencies[(block) & mask8]++;

		// this is one of the new lines. we isolate the first byte of the current block and the last
		// byte of the previous block to create the digram. then they are ORed together and masked off
		// to make sure there are only 2 bytes.
		digramFrequencies[(((block >> (7 * 8)) & 0xff) | ((previousBlock << (1 * 8)) & 0xff00)) & mask16]++;
		digramFrequencies[(block >> (6 * 8)) & mask16]++;
		digramFrequencies[(block >> (5 * 8)) & mask16]++;
		digramFrequencies[(block >> (4 * 8)) & mask16]++;
		digramFrequencies[(block >> (3 * 8)) & mask16]++;
		digramFrequencies[(block >> (2 * 8)) & mask16]++;
		digramFrequencies[(block >> (1 * 8)) & mask16]++;
		digramFrequencies[(block) & mask16]++;

		// these next 2 lines are similar to the one commented above, only now we are using 3 bytes.
		// the first line isolates the first byte of the new block and the last 2 of the previous block.
		// once they are ORed together they make up 3 bytes where the first 2 are on the previous block
		// and the third on the current block. the line after does the same thing but only one of the 
		// bytes is from the previous block and the other 2 are from the current block.
		trigramFrequencies[(((block >> (7 * 8)) & 0xff) | ((previousBlock << (1 * 8)) & 0xffff00)) & mask24]++;
		trigramFrequencies[(((block >> (6 * 8)) & 0xffff) | ((previousBlock << (2 * 8)) & 0xff0000)) & mask24]++;
		trigramFrequencies[(block >> (5 * 8)) & mask24]++;
		trigramFrequencies[(block >> (4 * 8)) & mask24]++;
		trigramFrequencies[(block >> (3 * 8)) & mask24]++;
		trigramFrequencies[(block >> (2 * 8)) & mask24]++;
		trigramFrequencies[(block >> (1 * 8)) & mask24]++;
		trigramFrequencies[(block)& mask24]++;

		// if we can't find the block in our current block in the octet map we will insert it.
		// otherwise we will increment that blocks count
		if (octetMap.find(block) == octetMap.end())
			octetMap.insert(pair<BIG, int>(block, 1));
		else 
			octetMap[block]++;

		// then we set the previous block to the current block and run it again
		previousBlock = block;
	}

	// if we still have bytes remaining they are not evenly divisible by 8. this case
	// only applies to unencrypted files. 
	if (fileLength != 0) {

		// we read the remaining bytes
		inputStream.read(buffer, fileLength);
		block = _byteswap_uint64(*(BIG*)buffer);
		// since the remaining bytes do not make a full octet we will not try to insert the 
		// block into the octet map

		// this will count the remaining on bits
		onBits += popcount64(block >> ((8 - fileLength) * 8));

		// depending on how many bytes we have left we will have different amounts of bytes,
		// digrams, and trigrams remaining. each of the cases contains the same code in the 
		// previous loop, there are just some lines removed for the lack of characters remaining
		switch (fileLength) {
		case 1:  {
			byteFrequencies[(block >> (7 * 8)) & mask8]++;

			// if our previous block was initialized and then there will be a digram and trigram that 
			// we can obtain
			if (previousBlockInitialized) {
				digramFrequencies[(((block >> (7 * 8) & 0xff) | ((previousBlock << (1 * 8)) & 0xff00)) & mask16)]++;

				trigramFrequencies[(((block >> (7 * 8)) & 0xff) | (((previousBlock << (1 * 8)) & 0xffff00))) & mask24]++;
			}
			

			break;
		}
		case 2: {
			byteFrequencies[(block >> (7 * 8)) & mask8]++;
			byteFrequencies[(block >> (6 * 8)) & mask8]++;

			if (previousBlockInitialized) 
				digramFrequencies[(((block >> (7 * 8) & 0xff) | ((previousBlock << (1 * 8)) & 0xff00)) & mask16)]++;
			digramFrequencies[(block >> (6 * 8)) & mask16]++;

			if (previousBlockInitialized) {
				trigramFrequencies[(((block >> (7 * 8)) & 0xff) | (((previousBlock << (1 * 8)) & 0xffff00))) & mask24]++;
				trigramFrequencies[(((block >> (6 * 8)) & 0xffff) | (((previousBlock << (2 * 8)) & 0xff0000))) & mask24]++;
			}
				

			break;
		}
		case 3: {
			byteFrequencies[(block >> (7 * 8)) & mask8]++;
			byteFrequencies[(block >> (6 * 8)) & mask8]++;
			byteFrequencies[(block >> (5 * 8)) & mask8]++;

			if (previousBlockInitialized)
				digramFrequencies[(((block >> (7 * 8)) & 0xff) & mask16) | (((previousBlock << (1 * 8)) & 0xff00))]++;
			digramFrequencies[(block >> (6 * 8)) & mask16]++;
			digramFrequencies[(block >> (5 * 8)) & mask16]++;

			if (previousBlockInitialized) {
				trigramFrequencies[(((block >> (7 * 8)) & 0xff) | (((previousBlock << (1 * 8)) & 0xffff00))) & mask24]++;
				trigramFrequencies[(((block >> (6 * 8)) & 0xffff) | (((previousBlock << (2 * 8)) & 0xff0000))) & mask24]++;
			}
			trigramFrequencies[(block >> 5) & mask24]++;

			break;
		}
		case 4: {
			byteFrequencies[(block >> (7 * 8)) & mask8]++;
			byteFrequencies[(block >> (6 * 8)) & mask8]++;
			byteFrequencies[(block >> (5 * 8)) & mask8]++;
			byteFrequencies[(block >> (4 * 8)) & mask8]++;

			if (previousBlockInitialized)
				digramFrequencies[(((block >> (7 * 8)) & 0xff) & mask16) | (((previousBlock << (1 * 8)) & 0xff00))]++;
			digramFrequencies[(block >> (6 * 8)) & mask16]++;
			digramFrequencies[(block >> (5 * 8)) & mask16]++;
			digramFrequencies[(block >> (4 * 8)) & mask16]++;

			if (previousBlockInitialized) {
				trigramFrequencies[(((block >> (7 * 8)) & 0xff) | (((previousBlock << (1 * 8)) & 0xffff00))) & mask24]++;
				trigramFrequencies[(((block >> (6 * 8)) & 0xffff) | (((previousBlock << (2 * 8)) & 0xff0000))) & mask24]++;
			}
			trigramFrequencies[(block >> (5 * 8)) & mask24]++;
			trigramFrequencies[(block >> (4 * 8)) & mask24]++;

			break;
		}
		case 5: {
			byteFrequencies[(block >> (7 * 8)) & mask8]++;
			byteFrequencies[(block >> (6 * 8)) & mask8]++;
			byteFrequencies[(block >> (5 * 8)) & mask8]++;
			byteFrequencies[(block >> (4 * 8)) & mask8]++;
			byteFrequencies[(block >> (3 * 8)) & mask8]++;

			if (previousBlockInitialized)
				digramFrequencies[(((block >> (7 * 8)) & 0xff) & mask16) | (((previousBlock << (1 * 8)) & 0xff00))]++;
			digramFrequencies[(block >> (6 * 8)) & mask16]++;
			digramFrequencies[(block >> (5 * 8)) & mask16]++;
			digramFrequencies[(block >> (4 * 8)) & mask16]++;
			digramFrequencies[(block >> (3 * 8)) & mask16]++;

			if (previousBlockInitialized) {
				trigramFrequencies[(((block >> (7 * 8)) & 0xff) | (((previousBlock << (1 * 8)) & 0xffff00))) & mask24]++;
				trigramFrequencies[(((block >> (6 * 8)) & 0xffff) | (((previousBlock << (2 * 8)) & 0xff0000))) & mask24]++;
			}
			trigramFrequencies[(block >> (5 * 8)) & mask24]++;
			trigramFrequencies[(block >> (4 * 8)) & mask24]++;
			trigramFrequencies[(block >> (3 * 8)) & mask24]++;

			break;
		}
		case 6: {
			byteFrequencies[(block >> (7 * 8)) & mask8]++;
			byteFrequencies[(block >> (6 * 8)) & mask8]++;
			byteFrequencies[(block >> (5 * 8)) & mask8]++;
			byteFrequencies[(block >> (4 * 8)) & mask8]++;
			byteFrequencies[(block >> (3 * 8)) & mask8]++;
			byteFrequencies[(block >> (2 * 8)) & mask8]++;

			if (previousBlockInitialized)
				digramFrequencies[(((block >> (7 * 8)) & 0xff) & mask16) | (((previousBlock << (1 * 8)) & 0xff00))]++;
			digramFrequencies[(block >> (6 * 8)) & mask16]++;
			digramFrequencies[(block >> (5 * 8)) & mask16]++;
			digramFrequencies[(block >> (4 * 8)) & mask16]++;
			digramFrequencies[(block >> (3 * 8)) & mask16]++;
			digramFrequencies[(block >> (2 * 8)) & mask16]++;

			if (previousBlockInitialized) {
				trigramFrequencies[(((block >> (7 * 8)) & 0xff) | (((previousBlock << (1 * 8)) & 0xffff00))) & mask24]++;
				trigramFrequencies[(((block >> (6 * 8)) & 0xffff) | (((previousBlock << (2 * 8)) & 0xff0000))) & mask24]++;
			}
			trigramFrequencies[(block >> (5 * 8)) & mask24]++;
			trigramFrequencies[(block >> (4 * 8)) & mask24]++;
			trigramFrequencies[(block >> (3 * 8)) & mask24]++;
			trigramFrequencies[(block >> (2 * 8)) & mask24]++;

			break;
		}
		case 7: {
			byteFrequencies[(block >> (7 * 8)) & mask8]++;
			byteFrequencies[(block >> (6 * 8)) & mask8]++;
			byteFrequencies[(block >> (5 * 8)) & mask8]++;
			byteFrequencies[(block >> (4 * 8)) & mask8]++;
			byteFrequencies[(block >> (3 * 8)) & mask8]++;
			byteFrequencies[(block >> (2 * 8)) & mask8]++;
			byteFrequencies[(block >> (1 * 8)) & mask8]++;

			if (previousBlockInitialized)
				digramFrequencies[(((block >> (7 * 8)) & 0xff) & mask16) | (((previousBlock << (1 * 8)) & 0xff00))]++;
			digramFrequencies[(block >> (6 * 8)) & mask16]++;
			digramFrequencies[(block >> (5 * 8)) & mask16]++;
			digramFrequencies[(block >> (4 * 8)) & mask16]++;
			digramFrequencies[(block >> (3 * 8)) & mask16]++;
			digramFrequencies[(block >> (2 * 8)) & mask16]++;
			digramFrequencies[(block >> (1 * 8)) & mask16]++;

			if (previousBlockInitialized) {
				trigramFrequencies[(((block >> (7 * 8)) & 0xff) | (((previousBlock << (1 * 8)) & 0xffff00))) & mask24]++;
				trigramFrequencies[(((block >> (6 * 8)) & 0xffff) | (((previousBlock << (2 * 8)) & 0xff0000))) & mask24]++;
			}
			trigramFrequencies[(block >> (5 * 8)) & mask24]++;
			trigramFrequencies[(block >> (4 * 8)) & mask24]++;
			trigramFrequencies[(block >> (3 * 8)) & mask24]++;
			trigramFrequencies[(block >> (2 * 8)) & mask24]++;
			trigramFrequencies[(block >> (1 * 8)) & mask24]++;

			break;

		}
		default:
			break;
		}
	}

	// since we are done with the input file we can close the input stream
	inputStream.close();

	// now we can calculate the off bits by finding the total number of bits and then
	// subtracting by the number of on bits
	BIG offBits = (originalLength * 8) - onBits;

	// all recorded metrics are then printed to the console and then the analysis is done
	cout << "Bit counts:" << endl << "On bits, Off bits" << endl << onBits << ", " << offBits << endl << endl;
	cout << "Byte frequencies: " << endl << "Byte value, Byte frequencies" << endl;
	for (int i = 0; i < 256; i++) {
		printf("0x%02X", i);
		cout << ", " << byteFrequencies[i] << endl;
	}

	cout << endl << "Digram frequencies: " << endl << "Digram value, Digram frequencies" << endl;

	// we exclude results that have 0 as a frequency count for digrams and octets
	// to save file space. for the trigrams we exclude counts of just 1 or 0 for
	// the same reason. if the trigrams are not limited excel runs out of rows for
	// all of the data.

	for (int i = 0; i < 65535; i++) {
		if (digramFrequencies[i] != 0) {
			printf("0x%04X", i);
			cout << ", " << digramFrequencies[i] << endl;
		}
	}

	cout << endl << "Trigram frequencies: " << endl << "Trigram value, Trigram frequencies" << endl;

	for (int i = 0; i < 16777215; i++) {
		if (trigramFrequencies[i] > 1) {
			printf("0x%06X", i);
			cout <<  ", " << trigramFrequencies[i] << endl;
		}
	}

	cout << endl << "Octet frequencies: " << endl << "Octet value, Octet frequencies" << endl;
	
	for (pair<BIG, int> pair : octetMap) {
		printf("0x%06X", pair.first);
		cout << ", " << pair.second << endl;
	}

	return 0;
}

// i wasn't sure what an efficient algorithm for hamming weight was so i looked this one up
// https://en.wikipedia.org/wiki/Hamming_weight
//This uses fewer arithmetic operations than any other known  
//implementation on machines with slow multiplication.
//This algorithm uses 17 arithmetic operations.
static int popcount64(BIG x) {
	x -= (x >> 1) & m1;             //put count of each 2 bits into those 2 bits
	x = (x & m2) + ((x >> 2) & m2); //put count of each 4 bits into those 4 bits 
	x = (x + (x >> 4)) & m4;        //put count of each 8 bits into those 8 bits 
	x += x >> 8;  //put count of each 16 bits into their lowest 8 bits
	x += x >> 16;  //put count of each 32 bits into their lowest 8 bits
	x += x >> 32;  //put count of each 64 bits into their lowest 8 bits
	return x & 0x7f;
}

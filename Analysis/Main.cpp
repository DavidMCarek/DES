#include <iostream>
#include <fstream>
#include <unordered_map>
#include "Main.h"

#define BIG unsigned long long
using namespace std;


const BIG m1 = 0x5555555555555555;
const BIG m2 = 0x3333333333333333;
const BIG m4 = 0x0f0f0f0f0f0f0f0f;

static int popcount64(BIG block);

static int byteFrequencies[256] = { 0 };
static int digramFrequencies[65536] = { 0 };
static int trigramFrequencies[16777216] = { 0 };

// this program should analyze an encryted and decrypted version of the
// shakespeare file. it needs to create a count of single bits (0 and 1)
// in both files. it also should analyze single byte frequencies. di-gram
// freqeuncies will also need to be counted by creating an array (65536 ints)
// this list will contain all 2 byte combinations in the file. the same will
// be done with tri-grams except the array will be 16777216 elements. 
// Octet frequency: Create an integer array of 640,000 elements
int main(int argc, char* argv[]) {
	
	// input: Analaysis <infile>

	ifstream inputStream;
	inputStream.open(argv[1], std::ios::binary);

	// if we couldn't open the file, let the user know and return
	if (inputStream.fail()) {
		cout << "Could not open input file" << endl;
		return 1;
	}

	inputStream.seekg(0, inputStream.end);
	BIG fileLength = inputStream.tellg();
	inputStream.seekg(0, inputStream.beg);

	BIG originalLength = fileLength;
	BIG onBits = 0;
	char * buffer = new char[8];
	BIG block = 0;
	BIG previousBlock;
	BIG mask8 = 0xff; // used for byte
	BIG mask16 = 0xffff; // used for digram
	BIG mask24 = 0xffffff; // used for trigram
	

	unordered_map<BIG, int> octetMap;


	if (fileLength > 7) {
		inputStream.read(buffer, 8);
		fileLength -= 8;

		previousBlock = _byteswap_uint64(*(BIG*)buffer);
		onBits += popcount64(previousBlock);

		byteFrequencies[(previousBlock >> 7) & mask8]++;
		byteFrequencies[(previousBlock >> 6) & mask8]++;
		byteFrequencies[(previousBlock >> 5) & mask8]++;
		byteFrequencies[(previousBlock >> 4) & mask8]++;
		byteFrequencies[(previousBlock >> 3) & mask8]++;
		byteFrequencies[(previousBlock >> 2) & mask8]++;
		byteFrequencies[(previousBlock >> 1) & mask8]++;
		byteFrequencies[(previousBlock) & mask8]++;

		digramFrequencies[(previousBlock >> 6) & mask16]++;
		digramFrequencies[(previousBlock >> 5) & mask16]++;
		digramFrequencies[(previousBlock >> 4) & mask16]++;
		digramFrequencies[(previousBlock >> 3) & mask16]++;
		digramFrequencies[(previousBlock >> 2) & mask16]++;
		digramFrequencies[(previousBlock >> 1) & mask16]++;
		digramFrequencies[(previousBlock) & mask16]++;

		trigramFrequencies[(previousBlock >> 5) & mask24]++;
		trigramFrequencies[(previousBlock >> 4) & mask24]++;
		trigramFrequencies[(previousBlock >> 3) & mask24]++;
		trigramFrequencies[(previousBlock >> 2) & mask24]++;
		trigramFrequencies[(previousBlock >> 1) & mask24]++;
		trigramFrequencies[(previousBlock) & mask24]++;

		octetMap.insert(pair<BIG, int>(previousBlock, 1));
	}

	while (fileLength > 7) {
		inputStream.read(buffer, 8);
		fileLength -= 8;
		block = _byteswap_uint64(*(BIG*)buffer);
		onBits += popcount64(block);
		
		byteFrequencies[(block >> 7) & mask8]++;
		byteFrequencies[(block >> 6) & mask8]++;
		byteFrequencies[(block >> 5) & mask8]++;
		byteFrequencies[(block >> 4) & mask8]++;
		byteFrequencies[(block >> 3) & mask8]++;
		byteFrequencies[(block >> 2) & mask8]++;
		byteFrequencies[(block >> 1) & mask8]++;
		byteFrequencies[(block) & mask8]++;

		digramFrequencies[(((block >> 7) & 0xff) & mask16) | (((previousBlock << 1) & 0xff00))]++;
		digramFrequencies[(block >> 6) & mask16]++;
		digramFrequencies[(block >> 5) & mask16]++;
		digramFrequencies[(block >> 4) & mask16]++;
		digramFrequencies[(block >> 3) & mask16]++;
		digramFrequencies[(block >> 2) & mask16]++;
		digramFrequencies[(block >> 1) & mask16]++;
		digramFrequencies[(block) & mask16]++;

		trigramFrequencies[(((block >> 7) & 0xff) | (((previousBlock << 1) & 0xffff00))) & mask24]++;
		trigramFrequencies[(((block >> 6) & 0xffff) | (((previousBlock << 2) & 0xff0000))) & mask24]++;
		trigramFrequencies[(block >> 5) & mask24]++;
		trigramFrequencies[(block >> 4) & mask24]++;
		trigramFrequencies[(block >> 3) & mask24]++;
		trigramFrequencies[(block >> 2) & mask24]++;
		trigramFrequencies[(block >> 1) & mask24]++;
		trigramFrequencies[(block)& mask24]++;

		if (octetMap.find(block) == octetMap.end())
			octetMap.insert(pair<BIG, int>(block, 1));
		else 
			octetMap[block]++;

		previousBlock = block;
	}

	if (fileLength != 0) {

		inputStream.read(buffer, fileLength);
		block = _byteswap_uint64(*(BIG*)buffer);

		onBits += popcount64(block >> 8 - fileLength);

		switch (fileLength) {
		case 1:  {
			byteFrequencies[(block >> 7) & mask8]++;

			digramFrequencies[(((block >> 7) & 0xff) & mask16) | (((previousBlock << 1) & 0xff00))]++;

			trigramFrequencies[(((block >> 7) & 0xff) | (((previousBlock << 1) & 0xffff00))) & mask24]++;

			break;
		}
		case 2: {
			byteFrequencies[(block >> 7) & mask8]++;
			byteFrequencies[(block >> 6) & mask8]++;

			digramFrequencies[(((block >> 7) & 0xff) & mask16) | (((previousBlock << 1) & 0xff00))]++;
			digramFrequencies[(block >> 6) & mask16]++;

			trigramFrequencies[(((block >> 7) & 0xff) | (((previousBlock << 1) & 0xffff00))) & mask24]++;
			trigramFrequencies[(((block >> 6) & 0xffff) | (((previousBlock << 2) & 0xff0000))) & mask24]++;

			break;
		}
		case 3: {
			byteFrequencies[(block >> 7) & mask8]++;
			byteFrequencies[(block >> 6) & mask8]++;
			byteFrequencies[(block >> 5) & mask8]++;

			digramFrequencies[(((block >> 7) & 0xff) & mask16) | (((previousBlock << 1) & 0xff00))]++;
			digramFrequencies[(block >> 6) & mask16]++;
			digramFrequencies[(block >> 5) & mask16]++;

			trigramFrequencies[(((block >> 7) & 0xff) | (((previousBlock << 1) & 0xffff00))) & mask24]++;
			trigramFrequencies[(((block >> 6) & 0xffff) | (((previousBlock << 2) & 0xff0000))) & mask24]++;
			trigramFrequencies[(block >> 5) & mask24]++;

			break;
		}
		case 4: {
			byteFrequencies[(block >> 7) & mask8]++;
			byteFrequencies[(block >> 6) & mask8]++;
			byteFrequencies[(block >> 5) & mask8]++;
			byteFrequencies[(block >> 4) & mask8]++;

			digramFrequencies[(((block >> 7) & 0xff) & mask16) | (((previousBlock << 1) & 0xff00))]++;
			digramFrequencies[(block >> 6) & mask16]++;
			digramFrequencies[(block >> 5) & mask16]++;
			digramFrequencies[(block >> 4) & mask16]++;

			trigramFrequencies[(((block >> 7) & 0xff) | (((previousBlock << 1) & 0xffff00))) & mask24]++;
			trigramFrequencies[(((block >> 6) & 0xffff) | (((previousBlock << 2) & 0xff0000))) & mask24]++;
			trigramFrequencies[(block >> 5) & mask24]++;
			trigramFrequencies[(block >> 4) & mask24]++;

			break;
		}
		case 5: {
			byteFrequencies[(block >> 7) & mask8]++;
			byteFrequencies[(block >> 6) & mask8]++;
			byteFrequencies[(block >> 5) & mask8]++;
			byteFrequencies[(block >> 4) & mask8]++;
			byteFrequencies[(block >> 3) & mask8]++;

			digramFrequencies[(((block >> 7) & 0xff) & mask16) | (((previousBlock << 1) & 0xff00))]++;
			digramFrequencies[(block >> 6) & mask16]++;
			digramFrequencies[(block >> 5) & mask16]++;
			digramFrequencies[(block >> 4) & mask16]++;
			digramFrequencies[(block >> 3) & mask16]++;

			trigramFrequencies[(((block >> 7) & 0xff) | (((previousBlock << 1) & 0xffff00))) & mask24]++;
			trigramFrequencies[(((block >> 6) & 0xffff) | (((previousBlock << 2) & 0xff0000))) & mask24]++;
			trigramFrequencies[(block >> 5) & mask24]++;
			trigramFrequencies[(block >> 4) & mask24]++;
			trigramFrequencies[(block >> 3) & mask24]++;

			break;
		}
		case 6: {
			byteFrequencies[(block >> 7) & mask8]++;
			byteFrequencies[(block >> 6) & mask8]++;
			byteFrequencies[(block >> 5) & mask8]++;
			byteFrequencies[(block >> 4) & mask8]++;
			byteFrequencies[(block >> 3) & mask8]++;
			byteFrequencies[(block >> 2) & mask8]++;

			digramFrequencies[(((block >> 7) & 0xff) & mask16) | (((previousBlock << 1) & 0xff00))]++;
			digramFrequencies[(block >> 6) & mask16]++;
			digramFrequencies[(block >> 5) & mask16]++;
			digramFrequencies[(block >> 4) & mask16]++;
			digramFrequencies[(block >> 3) & mask16]++;
			digramFrequencies[(block >> 2) & mask16]++;

			trigramFrequencies[(((block >> 7) & 0xff) | (((previousBlock << 1) & 0xffff00))) & mask24]++;
			trigramFrequencies[(((block >> 6) & 0xffff) | (((previousBlock << 2) & 0xff0000))) & mask24]++;
			trigramFrequencies[(block >> 5) & mask24]++;
			trigramFrequencies[(block >> 4) & mask24]++;
			trigramFrequencies[(block >> 3) & mask24]++;
			trigramFrequencies[(block >> 2) & mask24]++;

			break;
		}
		case 7: {
			byteFrequencies[(block >> 7) & mask8]++;
			byteFrequencies[(block >> 6) & mask8]++;
			byteFrequencies[(block >> 5) & mask8]++;
			byteFrequencies[(block >> 4) & mask8]++;
			byteFrequencies[(block >> 3) & mask8]++;
			byteFrequencies[(block >> 2) & mask8]++;
			byteFrequencies[(block >> 1) & mask8]++;

			digramFrequencies[(((block >> 7) & 0xff) & mask16) | (((previousBlock << 1) & 0xff00))]++;
			digramFrequencies[(block >> 6) & mask16]++;
			digramFrequencies[(block >> 5) & mask16]++;
			digramFrequencies[(block >> 4) & mask16]++;
			digramFrequencies[(block >> 3) & mask16]++;
			digramFrequencies[(block >> 2) & mask16]++;
			digramFrequencies[(block >> 1) & mask16]++;

			trigramFrequencies[(((block >> 7) & 0xff) | (((previousBlock << 1) & 0xffff00))) & mask24]++;
			trigramFrequencies[(((block >> 6) & 0xffff) | (((previousBlock << 2) & 0xff0000))) & mask24]++;
			trigramFrequencies[(block >> 5) & mask24]++;
			trigramFrequencies[(block >> 4) & mask24]++;
			trigramFrequencies[(block >> 3) & mask24]++;
			trigramFrequencies[(block >> 2) & mask24]++;
			trigramFrequencies[(block >> 1) & mask24]++;

			break;

		}
		default:
			break;
		}
	}

	inputStream.close();

	BIG offBits = (originalLength * 8) - onBits;

	cout << "On bits: " << onBits << " Off bits: " << offBits << endl << endl;

	cout << "Byte frequencies: " << endl;
	for (int i = 0; i < 256; i++) {
		cout << byteFrequencies[i] << endl;
	}

	cout << endl << "Digram frequencies: " << endl;

	for (int i = 0; i < 65535; i++) {
		if (digramFrequencies[i] != 0)
			cout << digramFrequencies[i] << endl;
	}

	cout << endl << "Trigram frequencies: " << endl;

	for (int i = 0; i < 16777215; i++) {
		if (trigramFrequencies[i] > 1)
			cout << trigramFrequencies[i] << endl;
	}

	cout << endl << "Octet frequencies: " << endl;
	
	int i = 0;
	for (pair<BIG, int> pair : octetMap) {
		cout << pair.second << endl;
		i++;
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

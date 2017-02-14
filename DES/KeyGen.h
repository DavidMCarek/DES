// EECS 4980:805 Inside Cryptography
// DES Project
// David Carek

// This file is the interface for the KeyGen.cpp file.

#pragma once
#include "Macros.h"

// this function takes in the key enetered from the cmd line and
// uses the key generation algorithm for DES to produce the 16
// 48 bit keys needed for each round of DES
void generateKeys(BIG inKey, BIG * keys);
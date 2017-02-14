// EECS 4980:805 Inside Cryptography
// DES Project
// David Carek

// This file is the interface for the DES.cpp file.

#pragma once
#include "Macros.h"

// runDES executes all of the internal parts of des
BIG runDES(BIG keys[], BIG block, bool encrypting);


#pragma once
#include "OpenSslPointers.h"

struct CryptographicKeyPair
{
	BioPointer PrivateKey;
	BioPointer PublicKey;
};

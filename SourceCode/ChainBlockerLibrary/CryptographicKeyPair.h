#pragma once
#include "OpenSslPointers.h"

namespace ChainBlocker
{
	struct CryptographicKeyPair
	{
		BioPointer PrivateKey;
		BioPointer PublicKey;
	};
}

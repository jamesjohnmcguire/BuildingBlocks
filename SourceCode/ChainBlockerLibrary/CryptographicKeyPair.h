#pragma once
#include "OpenSslPointers.h"

namespace ChainBlocker
{
	struct CryptographicKeyPair
	{
		BioSharedPointer PrivateKey;
		BioSharedPointer PublicKey;
	};
}

#pragma once
#include <stdio.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <exception>

#include "OpenSslPointers.h"

namespace ChainBlocker
{
	class Wallet
	{
	public:
		DllExport Wallet();

	private:
		BioPointer privateKey;
		BioPointer publicKey;
	};
}

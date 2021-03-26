#pragma once
#include <stdio.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <exception>

#include "CryptographicKey.h"
#include "OpenSslPointers.h"

namespace ChainBlocker
{
	class Wallet
	{
		public:
			DllExport std::string GetPrivateKeyPem();
			DllExport std::string GetPublicKeyPem();
			DllExport Wallet();

		private:
			std::shared_ptr<CryptographicKey> cryptographicKey;
	};
}

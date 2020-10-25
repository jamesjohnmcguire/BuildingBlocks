#include "pch.h"
#include "Cryptography.h"
#include "CryptographicKeyPair.h"
#include "Wallet.h"

namespace ChainBlocker
{
	Wallet::Wallet()
		: privateKey(nullptr), publicKey(nullptr)
	{
		Cryptography cryptography = Cryptography();

		CryptographicKeyPair* keyPair = cryptography.CreateKeyPair();

		if (keyPair != NULL)
		{
			privateKey = std::move(keyPair->PrivateKey);
			publicKey = std::move(keyPair->PublicKey);
		}
	}
}

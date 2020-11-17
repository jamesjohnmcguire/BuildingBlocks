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

		cryptographicKey = std::make_shared<CryptographicKey>(
			CryptographicKey(AlgorythmType::Rsa));

		CryptographicKeyPair* keyPair = cryptography.CreateKeyPair();

		if (keyPair != NULL)
		{
			privateKey = keyPair->PrivateKey;
			publicKey = keyPair->PublicKey;
		}
	}

	std::string Wallet::GetPrivateKeyPem()
	{
		CryptographicKey* key = cryptographicKey.get();

		std::string pemKey = key->GetPrivateKeyPem();

		return pemKey;
	}

	std::string Wallet::GetPublicKeyPem()
	{
		CryptographicKey* key = cryptographicKey.get();

		std::string pemKey = key->GetPublicKeyPem();

		return pemKey;
	}
}

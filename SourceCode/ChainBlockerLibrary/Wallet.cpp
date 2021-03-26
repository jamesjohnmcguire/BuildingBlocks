#include "pch.h"
#include "Cryptography.h"
#include "CryptographicKeyPair.h"
#include "Wallet.h"

namespace ChainBlocker
{
	Wallet::Wallet()
		: cryptographicKey(nullptr)
	{
		Cryptography cryptography = Cryptography();

		cryptographicKey = std::make_shared<CryptographicKey>(
			CryptographicKey(AlgorythmType::Rsa));
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

		std::string pemKey = key->GetPublicKeyPem(PemFormatType::Pkcs1Rsa);

		return pemKey;
	}
}

#include "pch.h"
#include "Cryptography.h"
#include "CryptographicKeyPair.h"
#include "Wallet.h"

Wallet::Wallet()
	: privateKey(nullptr), publicKey(nullptr)
{
	Cryptography cryptography = Cryptography();

	CryptographicKeyPair* keyPair = cryptography.CreateKeyPair();

	//if (keyPair != NULL)
	//{
	//	privateKey = keyPair->PrivateKey;
	//	publicKey = keyPair->PublicKey;
	//}
}

Wallet::~Wallet()
{
    BIO_free_all(privateKey);
    BIO_free_all(publicKey);
}

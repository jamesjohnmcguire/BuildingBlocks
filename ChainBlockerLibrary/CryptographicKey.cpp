#include "pch.h"
#include "CryptographicKey.h"

std::unique_ptr<CryptographicKey> CryptographicKey::Create(AlgorythmType algorythmType)
{
	std::unique_ptr<CryptographicKey> container = nullptr;

	switch (algorythmType)
	{
		case AlgorythmType::Rsa:
		{
			RsaSharedPointer rawKey = std::move(CreateRsaKey());
			break;
		}
		default:
			break;
	}

	return container;
}

std::string CryptographicKey::GetPrivateKeyPem()
{
	std::string privateKeyPem;

	BioSharedPointer privateKey = CreateKey(rawKey, false);

	if (privateKey != NULL)
	{
		std::string privateKeyPem = CreatePemKey(privateKey);
	}

	return privateKeyPem;
}

CryptographicKey::CryptographicKey(AlgorythmType algorythmType)
{
	switch (algorythmType)
	{
		case AlgorythmType::Rsa:
		{
			rawKey = CreateRsaKey();
			break;
		}
		default:
			break;
	}
}

BioPointer CryptographicKey::CreateKey(
	RsaSharedPointer rsaKey, bool isPublicKey)
{
	BioPointer key = nullptr;

	int successCode;

	const BIO_METHOD* method = BIO_s_mem();
	BIO* bioKey = BIO_new(method);

	if (isPublicKey == true)
	{
		successCode = PEM_write_bio_RSAPublicKey(bioKey, rsaKey.get());
	}
	else
	{
		successCode = PEM_write_bio_RSAPrivateKey(
			bioKey, rsaKey.get(), NULL, NULL, 0, NULL, NULL);
	}

	if (successCode != 1)
	{
		BIO_free_all(bioKey);
	}
	else
	{
		key = BioPointer(bioKey);
	}

	return key;
}

std::string CryptographicKey::CreatePemKey(BioSharedPointer key)
{
	std::string keyPem;

	int keyLength = BIO_pending(key.get());
	char* buffer = (char*)malloc((size_t)keyLength + 1);

	BIO_read(key.get(), buffer, keyLength);

	if (buffer != nullptr)
	{
		buffer[keyLength] = '\0';

		keyPem = buffer;
	}

	return keyPem;
}

RsaSharedPointer CryptographicKey::CreateRsaKey()
{
	RsaSharedPointer rsaKey = nullptr;
	BIGNUM* bigNumber = nullptr;
	unsigned long algorythmType = RSA_F4;
	int bits = 2048;

	bigNumber = BN_new();
	int successCode = BN_set_word(bigNumber, algorythmType);

	if (successCode == 1)
	{
		RSA* rsa = RSA_new();

		successCode = RSA_generate_key_ex(rsa, bits, bigNumber, nullptr);

		if (successCode == 1)
		{
			rsaKey.reset(rsa);
		}
	}

	BN_free(bigNumber);
	bigNumber = nullptr;

	return rsaKey;
}

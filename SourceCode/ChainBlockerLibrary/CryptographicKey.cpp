#include "pch.h"
#include "CryptographicKey.h"

std::unique_ptr<CryptographicKey> CryptographicKey::Create(
	AlgorythmType algorythmType)
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

std::string CryptographicKey::GetPrivateKeyBase64()
{
	std::string privateKeyBase64;

	if (publicKeyOnly == false)
	{
		BioSharedPointer privateKey =
			CreateKey(rawKey, false, PemFormatType::Pkcs1Rsa);

		if (privateKey != nullptr)
		{
			const std::string header = "-----BEGIN RSA PRIVATE KEY-----\n";
			const std::string footer = "-----END RSA PRIVATE KEY-----\n";

			std::string privateKeyPem = CreatePemKey(privateKey);

			privateKeyBase64 = RemoveSubString(privateKeyPem, header);
			privateKeyBase64 = RemoveSubString(privateKeyBase64, footer);
		}
	}

	return privateKeyBase64;
}

std::string CryptographicKey::GetPublicKeyBase64()
{
	std::string publicKeyBase64;

	BioSharedPointer publicKey =
		CreateKey(rawKey, true, PemFormatType::Pkcs1Rsa);

	if (publicKey != nullptr)
	{
		publicKeyBase64 = CreatePemKey(publicKey);
	}

	return publicKeyBase64;
}

std::string CryptographicKey::GetPrivateKeyPem()
{
	std::string privateKeyPem;

	if (publicKeyOnly == false)
	{
		BioSharedPointer privateKey =
			CreateKey(rawKey, false, PemFormatType::Pkcs1Rsa);

		if (privateKey != nullptr)
		{
			privateKeyPem = CreatePemKey(privateKey);
		}
	}

	return privateKeyPem;
}

std::string CryptographicKey::GetPublicKeyPem(PemFormatType formatType)
{
	std::string publicKeyPem;

	BioSharedPointer publicKey =
		CreateKey(rawKey, true, formatType);

	if (publicKey != nullptr)
	{
		publicKeyPem = CreatePemKey(publicKey);
	}

	return publicKeyPem;
}

CryptographicKey::CryptographicKey(AlgorythmType algorythmType)
	: publicKeyOnly(false)
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

CryptographicKey::CryptographicKey(
	const std::string& keyPem, bool publicKeyOnly)
{
	CryptographicKey::publicKeyOnly = publicKeyOnly;

	rawKey = GetRsaKey(keyPem, publicKeyOnly);
}

BioPointer CryptographicKey::CreateKey(
	RsaSharedPointer rsaKey, bool isPublicKey, PemFormatType formatType)
{
	BioPointer key = nullptr;

	int successCode;

	const BIO_METHOD* method = BIO_s_mem();
	BIO* bioKey = BIO_new(method);

#ifdef OPENSSL-1
	if (isPublicKey == true)
	{
		if (formatType == PemFormatType::Pkcs1Rsa)
		{
			// -----BEGIN RSA PUBLIC KEY-----
			successCode = PEM_write_bio_RSAPublicKey(bioKey, rsaKey.get());
		}
		else
		{
			// -----BEGIN PUBLIC KEY-----
			successCode = PEM_write_bio_RSA_PUBKEY(bioKey, rsaKey.get());
		}
	}
	else
	{
		successCode = PEM_write_bio_RSAPrivateKey(
			bioKey, rsaKey.get(), NULL, NULL, 0, NULL, NULL);
	}
#else
	successCode = 0;
#endif

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
#ifdef OPENSSL-1
		RSA* rsa = RSA_new();

		successCode = RSA_generate_key_ex(rsa, bits, bigNumber, nullptr);
#else
		RSA* rsa = nullptr;
		successCode = -1;
#endif

		if (successCode == 1)
		{
			rsaKey.reset(rsa);
		}
	}

	BN_free(bigNumber);
	bigNumber = nullptr;

	return rsaKey;
}

RsaSharedPointer CryptographicKey::GetRsaKey(
	std::string privateKey, bool isPublicKey)
{
	RsaSharedPointer rsaKey = nullptr;

	const char* string = privateKey.c_str();
	BIO* bioKey = BIO_new_mem_buf((void*)string, -1);

	if (bioKey != nullptr)
	{
		RSA* rsa = nullptr;

		if (isPublicKey == true)
		{
			rsa = PEM_read_bio_RSA_PUBKEY(bioKey, &rsa, nullptr, nullptr);
			rsa = PEM_read_bio_RSAPublicKey(bioKey, &rsa, nullptr, nullptr);
		}
		else
		{
			rsa = PEM_read_bio_RSAPrivateKey(bioKey, &rsa, nullptr, nullptr);
		}

		rsaKey.reset(rsa);
	}

	return rsaKey;
}

std::string CryptographicKey::RemoveSubString(
	std::string source,
	const std::string subString)
{
	size_t position = source.find(subString);
	if (position != std::string::npos)
	{
		source.erase(position, subString.length());
	}

	return source;
}

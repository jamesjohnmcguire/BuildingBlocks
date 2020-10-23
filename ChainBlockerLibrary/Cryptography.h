#pragma once
#include <memory>
#include <string>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "chainblocker.h"
#include "CryptographicKeyPair.h"

using namespace std;

struct BioDeleter
{
	void operator()(BIO* bio) const
	{
		if (bio)
		{
			BIO_free(bio);
		}
	}
};

struct EvpKeyDeleter
{
	void operator()(EVP_PKEY* evp) const
	{
		if (evp)
		{
			EVP_PKEY_free(evp);
		}
	}
};

struct RsaDeleter
{
	void operator()(RSA* rsa) const
	{
		if (rsa)
		{
			RSA_free(rsa);
			rsa = nullptr;
		}
	}
};

using EvpKeyPointer = std::unique_ptr<EVP_PKEY, EvpKeyDeleter>;
using BioPointer = std::unique_ptr<BIO, BioDeleter>;
using RsaPointer = std::unique_ptr<RSA, RsaDeleter>;

class Cryptography
{
	public:
		DllExport CryptographicKeyPair* CreateKeyPair();
		DllExport char* SignData(std::string privateKey, std::string plainText);
		DllExport bool VerifySignature(
			std::string publicKey,
			std::string plainText,
			char* signatureBase64);
		BioPointer CreateKey();
		DllExport ~Cryptography();

	private:
		unsigned char* Base64Decode(
			const char* input,
			size_t length,
			size_t* outputLength);
		char* Base64Encode(const unsigned char* input, size_t length);
		BIO* CreateKey(RSA* rsa, bool isPublicKey);
		char* CreatePemKey(BIO* key);
		RSA* CreateRsaKey();
		RsaPointer CreateRsaKeyNew();
		RsaPointer GetRsaPrivateKey(std::string privateKey);
		RSA* GetRsaPublicKey(std::string publicKey);
		unsigned char* RsaSignData(
			RsaPointer privateKey,
			const unsigned char* data,
			size_t dataLength,
			size_t* outputLength);
		bool RsaVerifySignature(RSA* publicKey,
			const unsigned char* data,
			size_t dataLength,
			const unsigned char* dataHash,
			size_t dataHashLength);
		bool VerifyKey(char* pemKey, bool isPublicKey);
};

#pragma once
#include <string>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "chainblocker.h"
#include "CryptographicKeyPair.h"

using namespace std;

class Cryptography
{
	public:
		DllExport CryptographicKeyPair* CreateKeyPair();
		DllExport char* SignData(std::string privateKey, std::string plainText);
		DllExport bool VerifySignature(
			std::string publicKey,
			std::string plainText,
			char* signatureBase64);

	private:
		unsigned char* Base64Decode(
			const char* input,
			size_t length,
			size_t* outputLength);
		char* Base64Encode(const unsigned char* input, size_t length);
		BIO* CreateKey(RSA* rsa, bool isPublicKey);
		char* CreatePemKey(BIO* key);
		RSA* CreateRsaKey();
		RSA* GetRsaPrivateKey(BIO* bioKey);
		RSA* GetRsaPrivateKey(std::string privateKey);
		RSA* GetRsaPublicKey(std::string publicKey);
		unsigned char* SignData(
			RSA* privateKey,
			const unsigned char* data,
			size_t dataLength,
			size_t* outputLength);
		bool VerifyKey(char* pemKey, bool isPublicKey);
		bool VerifySignature(RSA* publicKey,
			const unsigned char* data,
			size_t dataLength,
			const unsigned char* dataHash,
			size_t dataHashLength);
};

#pragma once
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "CryptographicKeyPair.h"

class Cryptography
{
	public:
		CryptographicKeyPair* CreateKeyPair();
		unsigned char* SignData(
			RSA* privateKey,
			const unsigned char* data,
			size_t dataLength);

	private:
		unsigned char* Base64Decode(const char* input, int length);
		char* Base64Encode(const unsigned char* input, int length);
		BIO* CreateKey(RSA* rsa, bool isPublicKey);
		char* CreatePemKey(BIO* key);
		RSA* GenerateRsaKey();
		RSA* GetRsaPrivateKey(BIO* bioKey);
		bool VerifyKey(char* pemKey, bool isPublicKey);
};

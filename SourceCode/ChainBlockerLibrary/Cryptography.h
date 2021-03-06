#pragma once
#include <memory>
#include <string>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "chainblocker.h"
#include "OpenSslPointers.h"
#include "CryptographicKeyPair.h"

namespace ChainBlocker
{
	// caller is responsible for freeing returned data.
	LIB_API(char*) SignData(
		char* privateKey,
		char* plainText);
	LIB_API(bool) VerifySignature(
		char* publicKey,
		char* plainText,
		char* signatureBase64);

	class Cryptography
	{
		public:
			DllExport CryptographicKeyPair* CreateKeyPair();
			DllExport std::unique_ptr<char> SignData(
				std::string privateKey,
				std::string plainText);
			DllExport bool VerifySignature(
				std::string publicKey,
				std::string plainText,
				std::string signatureBase64);
			DllExport ~Cryptography();

		private:
			std::unique_ptr<unsigned char> Base64Decode(
				std::string input,
				size_t length,
				size_t* outputLength);
			std::unique_ptr<char> Base64Encode(
				const unsigned char* input,
				size_t length);
			BioPointer CreateKey(RsaPointer rsaKey, bool isPublicKey);
			char* CreatePemKey(BioPointer key);
			RsaPointer CreateRsaKey();
			RsaPointer GetRsaKey(std::string privateKey, bool isPublicKey);
			unsigned char* RsaSignData(
				RsaPointer privateKey,
				const unsigned char* data,
				size_t dataLength,
				size_t* outputLength);
			bool RsaVerifySignature(RSA* publicKey,
				const unsigned char* data,
				size_t dataLength,
				const std::unique_ptr<unsigned char> dataHash,
				size_t dataHashLength);
			bool VerifyKey(char* pemKey, bool isPublicKey);
	};
}
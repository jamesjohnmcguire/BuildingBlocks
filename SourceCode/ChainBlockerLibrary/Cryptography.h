#pragma once
#include <memory>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "gtest/gtest.h"

#include "chainblocker.h"
#include "OpenSslPointers.h"
#include "CryptographicKeyPair.h"

#define FRIEND_TEST(test_case_name, test_name)\
friend class test_case_name##_##test_name##_Test

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
			DllExport std::vector<char> SignData(
				std::string privateKey,
				std::string plainText);
			DllExport bool VerifySignature(
				std::string publicKey,
				std::string plainText,
				std::string signatureBase64);
			DllExport ~Cryptography();

			// FRIEND_TEST(Cryptography, CreateEvpKey);
			DllExport EvpKeyPointer CreateEvpKey();

		private:
			BioPointer CreateKey(RsaSharedPointer rsaKey, bool isPublicKey);
			std::string CreatePemKey(BioSharedPointer key);
			RsaSharedPointer CreateRsaKey();
			RsaPointer GetRsaKey(std::string privateKey, bool isPublicKey);
			unsigned char* RsaSignData(
				RsaPointer privateKey,
				const unsigned char* data,
				size_t dataLength,
				size_t* outputLength);
			bool RsaVerifySignature(RSA* publicKey,
				const unsigned char* data,
				size_t dataLength,
				const std::vector<unsigned char> dataHash,
				size_t dataHashLength);
			bool VerifyKey(std::string pemKey, bool isPublicKey);
	};
}
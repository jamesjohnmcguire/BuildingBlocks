#include "pch.h"
#include "Cryptography.h"

namespace ChainBlocker
{
	// caller is responsible for freeing returned data.
	char* SignData(
		char* privateKey,
		char* plainText)
	{
		Cryptography cryptography = Cryptography();

		std::unique_ptr<char> signature =
			cryptography.SignData(privateKey, plainText);
		std::string buffer = signature.get();

		size_t size = buffer.size() + 1;

		void* rawOutput = malloc(size);
		char* output = reinterpret_cast<char*>(rawOutput);

		return output;
	}

	bool VerifySignature(
		char* publicKey,
		char* plainText,
		char* signatureBase64)
	{
		Cryptography cryptography = Cryptography();

		bool authentic = cryptography.VerifySignature(
			publicKey, plainText, signatureBase64);

		return authentic;
	}

	std::unique_ptr<unsigned char> Cryptography::Base64Decode(
		std::string input, size_t inputLength, size_t* outputLength)
	{
		const unsigned char* inputBuffer =
			reinterpret_cast<const unsigned char*>(input.c_str());

		const size_t bufferLength = 3 * inputLength / 4;

		unsigned char* rawBuffer =
			reinterpret_cast<unsigned char*>(calloc(bufferLength, 1));

		int inputBufferLength = static_cast<int>(inputLength);
		int actualLength =
			EVP_DecodeBlock(rawBuffer, inputBuffer, inputBufferLength);

		if (actualLength != bufferLength)
		{
			// log warning
		}

		size_t last = inputLength - 1;
		while (input[last] == '=')
		{
			actualLength--;
			last--;
		}

		*outputLength = actualLength;

		std::unique_ptr<unsigned char> output(rawBuffer);

		return output;
	}

	std::unique_ptr<char> Cryptography::Base64Encode(
		const unsigned char* input, size_t inputLength)
	{
		size_t encodeLength = 4 * ((inputLength + 2) / 3);

		// +1 for the terminating null
		encodeLength = encodeLength + 1;

		void* buffer = calloc(encodeLength, 1);
		char* charBuffer = reinterpret_cast<char*>(buffer);

		unsigned char* encodeBuffer =
			reinterpret_cast<unsigned char*>(charBuffer);

		int bufferLength = static_cast<int>(inputLength);
		int outputLength =
			EVP_EncodeBlock(encodeBuffer, input, bufferLength);

		if (encodeLength != outputLength)
		{
			// log warning
		}

		std::unique_ptr<char> output(charBuffer);

		return output;
	}

	// caller is responsible for freeing returned data.
	CryptographicKeyPair* Cryptography::CreateKeyPair()
	{
		CryptographicKeyPair* keyPair = NULL;

		RsaSharedPointer rsa = CreateRsaKey();

		if (rsa != NULL)
		{
			bool verified;
			keyPair = new CryptographicKeyPair;

			if (keyPair != NULL)
			{
				BioSharedPointer privateKey = CreateKey(rsa, false);

				if (privateKey != NULL)
				{
					std::string privateKeyPem = CreatePemKey(privateKey);

					if (!privateKeyPem.empty())
					{
						verified = VerifyKey(privateKeyPem, false);

						keyPair->PrivateKey = privateKey;
					}
				}

				BioSharedPointer publicKey = CreateKey(rsa, true);

				if (publicKey != NULL)
				{
					std::string publicKeyPem = CreatePemKey(publicKey);

					if (!publicKeyPem.empty())
					{
						verified = VerifyKey(publicKeyPem, true);

						keyPair->PublicKey = publicKey;
					}
				}
			}
		}

		return keyPair;
	}

	std::unique_ptr<char> Cryptography::SignData(
		std::string privateKey,
		std::string plainText)
	{
		std::unique_ptr<char> output = nullptr;
		size_t outputLength;

		RsaPointer privateRsaKey = GetRsaKey(privateKey, false);

		unsigned char* data = (unsigned char*)plainText.c_str();
		size_t dataLength = plainText.length();

		unsigned char* signedData = RsaSignData(
			std::move(privateRsaKey), data, dataLength, &outputLength);

		output = Base64Encode(signedData, outputLength);

		return output;
	}

	bool Cryptography::VerifySignature(
		std::string publicKey,
		std::string plainText,
		std::string signatureBase64)
	{
		size_t inputLength = signatureBase64.size();
		size_t outputLength;

		RsaPointer publicRSA = GetRsaKey(publicKey, true);

		std::unique_ptr<unsigned char> encodedData =
			Base64Decode(signatureBase64, inputLength, &outputLength);

		unsigned char* input = (unsigned char*)plainText.c_str();
		inputLength = plainText.length();

		bool result = RsaVerifySignature(
			publicRSA.get(),
			input,
			inputLength,
			std::move(encodedData),
			outputLength);

		return result;
	}

	Cryptography::~Cryptography()
	{
		ERR_free_strings();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
	}

	BioPointer Cryptography::CreateKey(
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

	std::string Cryptography::CreatePemKey(BioSharedPointer key)
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

	RsaSharedPointer Cryptography::CreateRsaKey()
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

	RsaPointer Cryptography::GetRsaKey(std::string privateKey, bool isPublicKey)
	{
		RsaPointer rsaKey = nullptr;

		const char* string = privateKey.c_str();
		BIO* bioKey = BIO_new_mem_buf((void*)string, -1);

		if (bioKey != nullptr)
		{
			RSA* rsa = nullptr;

			if (isPublicKey == true)
			{
				rsa = PEM_read_bio_RSA_PUBKEY(bioKey, &rsa, nullptr, nullptr);
			}
			else
			{
				rsa = PEM_read_bio_RSAPrivateKey(bioKey, &rsa, nullptr, nullptr);
			}

			rsaKey.reset(rsa);
		}

		return rsaKey;
	}

	// caller is responsible for freeing returned data.
	unsigned char* Cryptography::RsaSignData(
		RsaPointer privateKey,
		const unsigned char* data,
		size_t dataLength,
		size_t* outputLength)
	{
		unsigned char* signedData = NULL;

		EVP_MD_CTX* context = EVP_MD_CTX_create();
		EVP_PKEY* evpPrivateKey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(evpPrivateKey, privateKey.get());

		int successCode = EVP_DigestSignInit(
			context, NULL, EVP_sha256(), NULL, evpPrivateKey);

		if (successCode > 0)
		{
			successCode = EVP_DigestSignUpdate(context, data, dataLength);

			if (successCode > 0)
			{
				successCode = EVP_DigestSignFinal(context, NULL, outputLength);

				if (successCode > 0)
				{
					signedData = (unsigned char*)malloc(*outputLength);
					successCode =
						EVP_DigestSignFinal(context, signedData, outputLength);
				}
			}
		}

		EVP_MD_CTX_free(context);

		return signedData;
	}

	// caller is responsible for freeing returned data.
	bool Cryptography::RsaVerifySignature(
		RSA* publicKey,
		const unsigned char* data,
		size_t dataLength,
		const std::unique_ptr<unsigned char> dataHash,
		size_t dataHashLength)
	{
		bool verified = false;

		unsigned char* signedData = NULL;

		EVP_MD_CTX* context = EVP_MD_CTX_create();
		EVP_PKEY* evpPublicKey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(evpPublicKey, publicKey);

		int successCode =
			EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, evpPublicKey);

		if (successCode > 0)
		{
			successCode = EVP_DigestVerifyUpdate(context, data, dataLength);

			if (successCode > 0)
			{
				int status =
					EVP_DigestVerifyFinal(context, dataHash.get(), dataHashLength);

				if (status == 1)
				{
					verified = true;
				}
			}
		}

		EVP_MD_CTX_free(context);

		return verified;
	}

	bool Cryptography::VerifyKey(std::string pemKey, bool isPublicKey)
	{
		bool verified = false;

		size_t size = pemKey.size() + 1;
		void* buffer = malloc(size + 1);
		char* charBuffer = (char*)buffer;

		if (charBuffer != nullptr)
		{
			pemKey.copy(charBuffer, pemKey.size());

			BIO* key = BIO_new_mem_buf(buffer, -1);

			if (key != nullptr)
			{
				EVP_PKEY* evpKey = nullptr;

				if (isPublicKey == true)
				{
					evpKey = PEM_read_bio_PUBKEY(key, &evpKey, nullptr, nullptr);
				}
				else
				{
					// PEM_read_bio_RSAPrivateKey
					evpKey = PEM_read_bio_PrivateKey(key, &evpKey, nullptr, nullptr);
				}

				if (evpKey != nullptr)
				{
					verified = true;
				}

				BIO_free(key);
			}

			free(buffer);
		}

		return verified;
	}
}

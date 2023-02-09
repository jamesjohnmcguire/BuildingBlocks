#include "pch.h"
#include "Base64.h"
#include "Cryptography.h"

namespace ChainBlocker
{
	// caller is responsible for freeing returned data.
	char* SignData(
		char* privateKey,
		char* plainText)
	{
		Cryptography cryptography = Cryptography();

		std::vector<char> signature =
			cryptography.SignData(privateKey, plainText);
		std::string buffer = signature.data();

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

	std::vector<char> Cryptography::SignData(
		std::string privateKey,
		std::string plainText)
	{
		size_t outputLength;

		EvpKeyPointer privateRsaKey = GetRsaKey(privateKey, false);

		unsigned char* data = (unsigned char*)plainText.c_str();
		size_t dataLength = plainText.length();

		unsigned char* signedData = RsaSignData(
			std::move(privateRsaKey), data, dataLength, &outputLength);

		std::vector<char> output = Base64::Encode(signedData, outputLength);

		return output;
	}

	bool Cryptography::VerifySignature(
		std::string publicKey,
		std::string plainText,
		std::string signatureBase64)
	{
		size_t inputLength = signatureBase64.size();
		size_t outputLength;

		EvpKeyPointer publicRSA = GetRsaKey(publicKey, true);

		std::vector<unsigned char> encodedData =
			Base64::Decode(signatureBase64, inputLength, &outputLength);

		unsigned char* input = (unsigned char*)plainText.c_str();
		inputLength = plainText.length();

		bool result = RsaVerifySignature(
			publicRSA.get(),
			input,
			inputLength,
			encodedData,
			outputLength);

		return result;
	}

	Cryptography::~Cryptography()
	{
		ERR_free_strings();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
	}

	EvpKeyPointer Cryptography::CreateRsaKey()
	{
		EvpKeyPointer evpKey = nullptr;
		EVP_PKEY* evpRawKey = nullptr;

		EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

		int successCode = EVP_PKEY_keygen_init(context);

		if (successCode == 1)
		{
			successCode = EVP_PKEY_generate(context, &evpRawKey);

			if (successCode == 1)
			{
				evpKey.reset(evpRawKey);
			}
		}

		return evpKey;
	}

	BioPointer Cryptography::CreateKey(
		RsaSharedPointer rsaKey, bool isPublicKey)
	{
		BioPointer key = nullptr;

		int successCode;

		const BIO_METHOD* method = BIO_s_mem();
		BIO* bioKey = BIO_new(method);

#ifdef OPENSSL1
		if (isPublicKey == true)
		{
			successCode = PEM_write_bio_RSAPublicKey(bioKey, rsaKey.get());
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

	EvpKeyPointer Cryptography::GetRsaKey(
		std::string privateKey, bool isPublicKey)
	{
		EvpKeyPointer rsaKey = nullptr;

		const char* string = privateKey.c_str();
		BIO* bioKey = BIO_new_mem_buf((void*)string, -1);

		if (bioKey != nullptr)
		{
			EVP_PKEY* evpKey = nullptr;

			if (isPublicKey == true)
			{
				evpKey =
					PEM_read_bio_PUBKEY(bioKey, &evpKey, nullptr, nullptr);
			}
			else
			{
				evpKey =
					PEM_read_bio_PrivateKey(bioKey, &evpKey, nullptr, nullptr);
			}

			rsaKey.reset(evpKey);
		}

		return rsaKey;
	}

	// caller is responsible for freeing returned data.
	unsigned char* Cryptography::RsaSignData(
		EvpKeyPointer privateKey,
		const unsigned char* data,
		size_t dataLength,
		size_t* outputLength)
	{
		unsigned char* signedData = NULL;

		EVP_MD_CTX* context = EVP_MD_CTX_create();
#ifdef OPENSSL1
		EVP_PKEY* evpPrivateKey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(evpPrivateKey, privateKey.get());
#else
		EVP_PKEY* evpPrivateKey = nullptr;
#endif

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
		EVP_PKEY* publicKey,
		const unsigned char* data,
		size_t dataLength,
		const std::vector<unsigned char> dataHash,
		size_t dataHashLength)
	{
		bool verified = false;

		unsigned char* signedData = NULL;

		EVP_MD_CTX* context = EVP_MD_CTX_create();
		EVP_PKEY* evpPublicKey = EVP_PKEY_new();
#ifdef OPENSSL1
		EVP_PKEY_assign_RSA(evpPublicKey, publicKey);
#endif

		int successCode = EVP_DigestVerifyInit(
			context, NULL, EVP_sha256(), NULL, evpPublicKey);

		if (successCode > 0)
		{
			successCode = EVP_DigestVerifyUpdate(context, data, dataLength);

			if (successCode > 0)
			{
				int status = EVP_DigestVerifyFinal(
					context, dataHash.data(), dataHashLength);

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

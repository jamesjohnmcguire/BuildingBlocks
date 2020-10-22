#include "pch.h"
#include "Cryptography.h"

unsigned char* Cryptography::Base64Decode(
	const char* input, size_t inputLength, size_t* outputLength)
{
	const unsigned char* inputBuffer =
		reinterpret_cast<const unsigned char*>(input);

	const size_t bufferLength = 3 * inputLength / 4;
	unsigned char* output =
		reinterpret_cast<unsigned char*>(calloc(bufferLength, 1));

	int decodeLength = static_cast<int>(inputLength);
	int actualLength = EVP_DecodeBlock(output, inputBuffer, decodeLength);

	if (decodeLength != *outputLength)
	{
		// log warning
	}

	// remove null terminators
	size_t modifiedLength = actualLength;
	*outputLength = modifiedLength - 2;

	return output;
}

char* Cryptography::Base64Encode(
	const unsigned char* input, size_t inputLength)
{
	size_t encodeLength = 4 * ((inputLength + 2) / 3);

	// +1 for the terminating null
	encodeLength = encodeLength + 1;

	char* output = reinterpret_cast<char*>(calloc(encodeLength, 1));
	unsigned char* encodeBuffer = reinterpret_cast<unsigned char*>(output);

	int bufferLength = static_cast<int>(inputLength);
	int outputLength =
		EVP_EncodeBlock(encodeBuffer, input, bufferLength);

	if (encodeLength != outputLength)
	{
		// log warning
	}

	return output;
}

// caller is responsible for freeing returned data.
CryptographicKeyPair* Cryptography::CreateKeyPair()
{
	CryptographicKeyPair* keyPair = NULL;

	RSA* rsa = GenerateRsaKey();

	if (rsa != NULL)
	{
		bool verified;
		keyPair = new CryptographicKeyPair;

		if (keyPair != NULL)
		{
			BIO* privateKey = CreateKey(rsa, false);

			if (privateKey != NULL)
			{
				char* privateKeyPem = CreatePemKey(privateKey);

				if (privateKeyPem != NULL)
				{
					verified = VerifyKey(privateKeyPem, false);
					free(privateKeyPem);

					keyPair->PrivateKey = privateKey;
				}
			}

			BIO* publicKey = CreateKey(rsa, true);

			if (publicKey != NULL)
			{
				char* publicKeyPem = CreatePemKey(publicKey);

				if (publicKeyPem != NULL)
				{
					verified = VerifyKey(publicKeyPem, true);
					free(publicKeyPem);

					keyPair->PublicKey = publicKey;
				}
			}

			RSA_free(rsa);
		}
	}

	return keyPair;
}

// caller is responsible for freeing returned data.
unsigned char* Cryptography::SignData(
	RSA* privateKey,
	const unsigned char* data,
	size_t dataLength,
	size_t* outputLength)
{
	unsigned char* signedData = NULL;

	EVP_MD_CTX* context = EVP_MD_CTX_create();
	EVP_PKEY* evpPrivateKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(evpPrivateKey, privateKey);

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
				successCode = EVP_DigestSignFinal(context, signedData, outputLength);
			}
		}
	}

	EVP_MD_CTX_free(context);

	return signedData;
}

char* Cryptography::SignMessage(std::string privateKey, std::string plainText)
{
	char* output = nullptr;
	size_t outputLength;

	RSA* privateRsaKey = GetRsaPrivateKey(privateKey);

	unsigned char* data = (unsigned char*)plainText.c_str();
	size_t dataLength = plainText.length();

	unsigned char* signedData =
		SignData(privateRsaKey, data, dataLength, &outputLength);

	output = Base64Encode(signedData, outputLength);

	return output;
}

BIO* Cryptography::CreateKey(RSA* rsa, bool isPublicKey)
{
    int successCode;
    BIO* key = BIO_new(BIO_s_mem());

    if (isPublicKey == true)
    {
        successCode = PEM_write_bio_RSAPublicKey(key, rsa);
    }
    else
    {
        successCode = PEM_write_bio_RSAPrivateKey(
            key, rsa, NULL, NULL, 0, NULL, NULL);
    }

    if (successCode != 1)
    {
        BIO_free_all(key);
    }

    return key;
}

char* Cryptography::CreatePemKey(BIO* key)
{
    int keyLength = BIO_pending(key);
    char* keyPem = (char*)malloc((size_t)keyLength + 1);

    BIO_read(key, keyPem, keyLength);

    if (keyPem != NULL)
    {
        keyPem[keyLength] = '\0';
    }

    return keyPem;
}

RSA* Cryptography::GenerateRsaKey()
{
    RSA* rsaKey = nullptr;
    BIGNUM* bigNumber = nullptr;
    unsigned long algorythmType = RSA_F4;
    int bits = 2048;

    bigNumber = BN_new();
    int successCode = BN_set_word(bigNumber, algorythmType);

    if (successCode == 1)
    {
		rsaKey = RSA_new();
        successCode = RSA_generate_key_ex(rsaKey, bits, bigNumber, nullptr);

        if (successCode != 1)
        {
            RSA_free(rsaKey);
			rsaKey = nullptr;
        }
    }

    BN_free(bigNumber);

    return rsaKey;
}


RSA* Cryptography::GetRsaPrivateKey(BIO* bioKey)
{
	RSA* rsaKey = NULL;

	return rsaKey;
}

RSA* Cryptography::GetRsaPrivateKey(std::string privateKey)
{
	RSA* rsaKey = nullptr;

	const char* string = privateKey.c_str();
	BIO* bioKey = BIO_new_mem_buf((void*)string, -1);

	if (bioKey != nullptr)
	{
		rsaKey = PEM_read_bio_RSAPrivateKey(bioKey, &rsaKey, nullptr, nullptr);
	}

	return rsaKey;
}

RSA* Cryptography::GetRsaPublicKey(std::string publicKey)
{
	RSA* rsaKey = nullptr;

	const char* string = publicKey.c_str();
	BIO* bioKey = BIO_new_mem_buf((void*)string, -1);

	if (bioKey != nullptr)
	{
		rsaKey = PEM_read_bio_RSA_PUBKEY(bioKey, &rsaKey, nullptr, nullptr);
	}

	return rsaKey;
}

bool Cryptography::VerifyKey(char* pemKey, bool isPublicKey)
{
    bool verified = false;

    BIO* key = BIO_new_mem_buf((void*)pemKey, -1);
    if (key != NULL)
    {
        EVP_PKEY* evpKey = NULL;

        if (isPublicKey == true)
        {
            evpKey = PEM_read_bio_PUBKEY(key, &evpKey, NULL, NULL);
        }
        else
        {
				// PEM_read_bio_RSAPrivateKey
				evpKey = PEM_read_bio_PrivateKey(key, &evpKey, NULL, NULL);
        }

        if (evpKey != NULL)
        {
            verified = true;
        }

        BIO_free(key);
    }

    return verified;
}


// caller is responsible for freeing returned data.
bool Cryptography::VerifySignature(
	RSA * publicKey,
	const unsigned char* data,
	size_t dataLength,
	const unsigned char* dataHash,
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
				EVP_DigestVerifyFinal(context, dataHash, dataHashLength);

			if (status == 1)
			{
				verified = true;	
			}
		}
	}

	EVP_MD_CTX_free(context);

	return verified;
}

bool Cryptography::VerifySignature(
	std::string publicKey,
	std::string plainText,
	char* signatureBase64)
{
	size_t inputLength = strlen(signatureBase64);
	size_t outputLength;

	RSA* publicRSA = GetRsaPublicKey(publicKey);
	unsigned char* encMessage =
		Base64Decode(signatureBase64, inputLength, &outputLength);

	unsigned char* input = (unsigned char* )plainText.c_str();
	inputLength = plainText.length();

	bool result = VerifySignature(
		publicRSA, input, inputLength, encMessage, outputLength);

	return result;
}

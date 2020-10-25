#include "pch.h"
#include "Cryptography.h"

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

// caller is responsible for freeing returned data.
CryptographicKeyPair* Cryptography::CreateKeyPair()
{
	CryptographicKeyPair* keyPair = NULL;

	RsaPointer rsa = CreateRsaKey();

	if (rsa != NULL)
	{
		bool verified;
		keyPair = new CryptographicKeyPair;

		if (keyPair != NULL)
		{
			BioPointer privateKey = CreateKey(std::move(rsa), false);

			if (privateKey != NULL)
			{
				char* privateKeyPem = CreatePemKey(std::move(privateKey));

				if (privateKeyPem != NULL)
				{
					verified = VerifyKey(privateKeyPem, false);
					free(privateKeyPem);

					keyPair->PrivateKey = std::move(privateKey);
				}
			}

			BioPointer publicKey = CreateKey(std::move(rsa), true);

			if (publicKey != NULL)
			{
				char* publicKeyPem = CreatePemKey(std::move(publicKey));

				if (publicKeyPem != NULL)
				{
					verified = VerifyKey(publicKeyPem, true);
					free(publicKeyPem);

					keyPair->PublicKey = std::move(publicKey);
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

	unsigned char* signedData =
		RsaSignData(std::move(privateRsaKey), data, dataLength, &outputLength);

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

std::unique_ptr<unsigned char> Cryptography::Base64Decode(
	std::string input, size_t inputLength, size_t* outputLength)
{
	const unsigned char* inputBuffer =
		reinterpret_cast<const unsigned char*>(input.c_str());

	const size_t bufferLength = 3 * inputLength / 4;

	unsigned char* rawBuffer =
		reinterpret_cast<unsigned char*>(calloc(bufferLength, 1));

	std::unique_ptr<unsigned char> output(rawBuffer);

	int decodeLength = static_cast<int>(inputLength);
	int actualLength =
		EVP_DecodeBlock(output.get(), inputBuffer, decodeLength);

	if (decodeLength != *outputLength)
	{
		// log warning
	}

	// remove null terminators
	size_t modifiedLength = actualLength;
	*outputLength = modifiedLength - 2;

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

	std::unique_ptr<char> output(charBuffer);

	unsigned char* encodeBuffer = 
		reinterpret_cast<unsigned char*>(output.get());

	int bufferLength = static_cast<int>(inputLength);
	int outputLength =
		EVP_EncodeBlock(encodeBuffer, input, bufferLength);

	if (encodeLength != outputLength)
	{
		// log warning
	}

	return output;
}

BioPointer Cryptography::CreateKey(RsaPointer rsaKey, bool isPublicKey)
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

char* Cryptography::CreatePemKey(BioPointer key)
{
    int keyLength = BIO_pending(key.get());
    char* keyPem = (char*)malloc((size_t)keyLength + 1);

    BIO_read(key.get(), keyPem, keyLength);

    if (keyPem != NULL)
    {
        keyPem[keyLength] = '\0';
    }

    return keyPem;
}

RsaPointer Cryptography::CreateRsaKey()
{
	RsaPointer rsaKey = nullptr;
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
			RsaPointer rsaKey(rsa);
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
	RSA * publicKey,
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

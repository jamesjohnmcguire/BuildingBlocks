#include "pch.h"
#include "Cryptography.h"

unsigned char* Cryptography::Base64Decode(const char* input, int length)
{
	const int decodeLength = 3 * length / 4;
	size_t bufferLength = (size_t)decodeLength + 1;
	unsigned char* output = reinterpret_cast<unsigned char*>(calloc(bufferLength, 1));
	const unsigned char* inputBuffer = reinterpret_cast<const unsigned char*>(input);

	const int outputLength = EVP_DecodeBlock(output, inputBuffer, length);

	if (decodeLength != outputLength)
	{
		// log warning
	}

	return output;
}

char* Cryptography::Base64Encode(const unsigned char* input, int length)
{
	const int encodeLength = 4 * ((length + 2) / 3);

	// +1 for the terminating null
	size_t bufferLength = (size_t)encodeLength + 1;
	char* output = reinterpret_cast<char*>(calloc(bufferLength, 1));
	unsigned char* encodeBuffer = reinterpret_cast<unsigned char*>(output);
	const int outputLength = EVP_EncodeBlock(encodeBuffer, input, length);
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
	size_t dataLength)
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
			size_t outputLength;
			successCode = EVP_DigestSignFinal(context, NULL, &outputLength);

			if (successCode > 0)
			{
				unsigned char* output = (unsigned char*)malloc(outputLength);
				successCode = EVP_DigestSignFinal(context, output, &outputLength);
			}
		}
	}

	EVP_MD_CTX_free(context);

	return signedData;
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
    RSA* rsa = NULL;
    BIGNUM* bigNumber = NULL;
    unsigned long algorythmType = RSA_F4;
    int bits = 2048;

    bigNumber = BN_new();
    int successCode = BN_set_word(bigNumber, algorythmType);

    if (successCode == 1)
    {
        rsa = RSA_new();
        successCode = RSA_generate_key_ex(rsa, bits, bigNumber, NULL);

        if (successCode != 1)
        {
            RSA_free(rsa);
            rsa = NULL;
        }
    }

    BN_free(bigNumber);

    return rsa;
}

RSA* Cryptography::GetRsaPrivateKey(BIO* bioKey)
{
	RSA* rsaKey = NULL;

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


/*

bool RSAVerifySignature(RSA* rsa,
	unsigned char* MsgHash,
	size_t MsgHashLen,
	const char* Msg,
	size_t MsgLen,
	bool* Authentic) {
	*Authentic = false;
	EVP_PKEY* pubKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pubKey, rsa);
	EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

	if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0) {
		return false;
	}
	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
		return false;
	}
	int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
	if (AuthStatus == 1) {
		*Authentic = true;
		EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
		return true;
	}
	else if (AuthStatus == 0) {
		*Authentic = false;
		EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
		return true;
	}
	else {
		*Authentic = false;
		EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
		return false;
	}
}

bool verifySignature(std::string publicKey, std::string plainText, char* signatureBase64) {
	RSA* publicRSA = createPublicRSA(publicKey);
	unsigned char* encMessage;
	size_t encMessageLength;
	bool authentic;
	Base64Decode(signatureBase64, &encMessage, &encMessageLength);
	bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
	return result & authentic;
}

int main() {
	std::string plainText = "My secret message.\n";
	char* signature = signMessage(privateKey, plainText);
	bool authentic = verifySignature(publicKey, "My secret message.\n", signature);
	if (authentic) {
		std::cout << "Authentic" << std::endl;
	}
	else {
		std::cout << "Not Authentic" << std::endl;
	}
}

*/
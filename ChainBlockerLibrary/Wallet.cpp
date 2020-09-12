#include "pch.h"
#include "Wallet.h"

Wallet::~Wallet()
{
    BIO_free_all(privateKey);
    BIO_free_all(publicKey);
}

bool Wallet::GenerateKeyPair()
{
    bool successCode = false;

    RSA* rsa = GenerateRsaKey();

    if (rsa != NULL)
    {
        bool verified;

        privateKey = CreateKey(rsa, false);

        if (privateKey != NULL)
        {
            char* privateKeyPem = CreatePemKey(privateKey);
            verified = VerifyKey(privateKeyPem, false);
        }

        publicKey = CreateKey(rsa, true);

        if (publicKey != NULL)
        {
            char* publicKeyPem = CreatePemKey(publicKey);
            verified = VerifyKey(publicKeyPem, true);
        }

        RSA_free(rsa);

        successCode = true;
    }

    return successCode;
}

BIO* Wallet::CreateKey(RSA* rsa, bool isPublicKey)
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

char* Wallet::CreatePemKey(BIO* key)
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

RSA* Wallet::GenerateRsaKey()
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

bool Wallet::VerifyKey(char* pemKey, bool isPublicKey)
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

#pragma once
#include <stdio.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <exception>

class Wallet
{
	public:
		~Wallet();
		bool GenerateKeyPair();

	private:
		BIO* privateKey;
		BIO* publicKey;

		BIO* CreateKey(RSA* rsa, bool isPublicKey);
		char* CreatePemKey(BIO* key);
		RSA* GenerateRsaKey();
		bool VerifyKey(char* pemKey, bool isPublicKey);
};

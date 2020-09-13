#pragma once
#include <stdio.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <exception>

class Wallet
{
	public:
		Wallet();
		~Wallet();

	private:
		BIO* privateKey;
		BIO* publicKey;
};

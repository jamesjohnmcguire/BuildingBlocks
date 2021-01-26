#pragma once
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

struct BioDeleter
{
	void operator()(BIO* bio) const
	{
		if (bio)
		{
			BIO_free(bio);
		}
	}
};

struct EvpKeyDeleter
{
	void operator()(EVP_PKEY* evp) const
	{
		if (evp)
		{
			EVP_PKEY_free(evp);
		}
	}
};

struct RsaDeleter
{
	void operator()(RSA* rsa) const
	{
		if (rsa)
		{
			RSA_free(rsa);
			rsa = nullptr;
		}
	}
};

using EvpKeyPointer = std::unique_ptr<EVP_PKEY, EvpKeyDeleter>;
using BioPointer = std::unique_ptr<BIO, BioDeleter>;
using RsaPointer = std::unique_ptr<RSA, RsaDeleter>;

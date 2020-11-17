#pragma once
#include <memory>
#include <string>

#include "AlgorythmType.h"
#include "OpenSslPointers.h"

class CryptographicKey
{
	public:
		static std::unique_ptr<CryptographicKey> Create(AlgorythmType algorythmType);
		std::string GetPrivateKeyPem();
		std::string GetPublicKeyPem();

		CryptographicKey(AlgorythmType algorythmType);

	private:
		BioPointer CreateKey(RsaSharedPointer rsaKey, bool isPublicKey);
		std::string CreatePemKey(BioSharedPointer key);
		static RsaSharedPointer CreateRsaKey();

		RsaSharedPointer rawKey;
};

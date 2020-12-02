#pragma once
#include <memory>
#include <string>

#include "chainblocker.h"
#include "AlgorythmType.h"
#include "OpenSslPointers.h"

class CryptographicKey
{
	public:
		DllExport static std::unique_ptr<CryptographicKey> Create(
			AlgorythmType algorythmType);
		DllExport std::string GetPrivateKeyBase64();
		DllExport std::string GetPublicKeyBase64();
		DllExport std::string GetPrivateKeyPem();
		DllExport std::string GetPublicKeyPem();

		DllExport CryptographicKey(AlgorythmType algorythmType);

	private:
		BioPointer CreateKey(RsaSharedPointer rsaKey, bool isPublicKey);
		std::string CreatePemKey(BioSharedPointer key);
		static RsaSharedPointer CreateRsaKey();
		std::string RemoveSubString(
			std::string source, const std::string subString);

		RsaSharedPointer rawKey;
};

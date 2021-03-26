#pragma once
#include <memory>
#include <string>

#include "chainblocker.h"
#include "AlgorythmType.h"
#include "OpenSslPointers.h"
#include "PemFormatType.h"

class CryptographicKey
{
	public:
		DllExport static std::unique_ptr<CryptographicKey> Create(
			AlgorythmType algorythmType);
		DllExport std::string GetPrivateKeyBase64();
		DllExport std::string GetPublicKeyBase64();
		DllExport std::string GetPrivateKeyPem();
		DllExport std::string GetPublicKeyPem(PemFormatType formatType);

		DllExport CryptographicKey(AlgorythmType algorythmType);
		DllExport CryptographicKey(
			const std::string& keyPem,
			bool publicKeyOnly = false);

	private:
		BioPointer CreateKey(
			RsaSharedPointer rsaKey,
			bool isPublicKey,
			PemFormatType formatType);
		std::string CreatePemKey(BioSharedPointer key);
		static RsaSharedPointer CreateRsaKey();
		RsaSharedPointer GetRsaKey(std::string privateKey, bool isPublicKey);
		std::string RemoveSubString(
			std::string source, const std::string subString);

		bool publicKeyOnly;
		RsaSharedPointer rawKey;
};

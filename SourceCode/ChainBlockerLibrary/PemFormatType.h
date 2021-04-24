#pragma once

enum class PemFormatType
{
	// PKCS#1  (PEM header : BEGIN RSA PUBLIC KEY)
	Pkcs1Rsa,
	// X.509 (PEM header : BEGIN PUBLIC KEY)
	SubjectPublicKeyInfo
};

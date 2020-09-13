#pragma once

struct CryptographicKeyPair
{
	BIO* PrivateKey;
	BIO* PublicKey;
};

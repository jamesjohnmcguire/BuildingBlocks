#include "pch.h"
#include <sstream>

#include "sha256.h"
#include "Transaction.h"

namespace ChainBlocker
{
	std::string Transaction::CalulateHash()
	{
		std::string buffer = std::string();

		std::string hash = sha256(buffer);

		return hash;
	}

	int Transaction::GetAmount()
	{
		return amount;
	}

	std::string Transaction::GetId()
	{
		return transactionId;
	}

	std::string Transaction::GetSender()
	{
		std::string senderPrivateKeyPem = senderPrivateKey.GetPrivateKeyPem();
		return senderPrivateKeyPem;
	}

	std::string Transaction::GetRecipient()
	{
		std::string recipientPublicKeyPem =
			senderPrivateKey.GetPublicKeyPem(PemFormatType::Pkcs1Rsa);
		return recipientPublicKeyPem;
	}

	std::string Transaction::GetSignature()
	{
		return signature;
	}

	bool Transaction::VerifySignature()
	{
		return false;
	}

	Transaction::Transaction(
		std::string senderPrivateKeyPem,
		std::string recipientPublicKeyPem,
		int amount,
		std::vector<TransactionInput> inputs)
		:	senderPrivateKey(CryptographicKey(senderPrivateKeyPem)),
			recipientPublicKey(CryptographicKey(recipientPublicKeyPem, true)),
			amount(amount),
			inputs(inputs)
	{
		outputs = std::vector<TransactionOutput>();

		CreateSignature();
	}

	void Transaction::CreateSignature()
	{
		std::string senderPrivateKeyPem = senderPrivateKey.GetPrivateKeyPem();
		std::string recipientPublicKeyPem =
			recipientPublicKey.GetPublicKeyPem(PemFormatType::Pkcs1Rsa);

		std::stringstream streamBuffer;
		streamBuffer << senderPrivateKeyPem << recipientPublicKeyPem << amount;

		std::string buffer = streamBuffer.str();
		signature = sha256(buffer);
	}
}

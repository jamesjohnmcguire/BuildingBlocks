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
		return senderPrivateKey;
	}

	std::string Transaction::GetRecipient()
	{
		return recipientPublicKey;
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
		std::string senderPrivateKey,
		std::string recipientPublicKey,
		int amount,
		std::vector<TransactionInput> inputs)
		:	senderPrivateKey(senderPrivateKey),
			recipientPublicKey(recipientPublicKey),
			amount(amount),
			inputs(inputs)
	{
		outputs = std::vector<TransactionOutput>();

		CreateSignature();
	}

	void Transaction::CreateSignature()
	{
		std::stringstream streamBuffer;
		streamBuffer << senderPrivateKey << recipientPublicKey << amount;

		std::string buffer = streamBuffer.str();
		signature = sha256(buffer);
	}
}

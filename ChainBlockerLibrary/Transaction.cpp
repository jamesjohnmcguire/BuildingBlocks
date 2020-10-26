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
		return sender;
	}

	std::string Transaction::GetRecipient()
	{
		return recipient;
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
		std::string sender,
		std::string recipient,
		int amount,
		std::vector<TransactionInput> inputs)
		: sender(sender), recipient(recipient), amount(amount), inputs(inputs)
	{
		outputs = std::vector<TransactionOutput>();

		CreateSignature();
	}

	void Transaction::CreateSignature()
	{
		std::stringstream streamBuffer;
		streamBuffer << sender << recipient << amount;

		std::string buffer = streamBuffer.str();
		signature = sha256(buffer);
	}
}

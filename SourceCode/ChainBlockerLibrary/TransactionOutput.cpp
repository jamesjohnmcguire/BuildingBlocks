#include "pch.h"
#include <sstream>

#include "sha256.h"
#include "TransactionOutput.h"

namespace ChainBlocker
{
	TransactionOutput::TransactionOutput()
		: value(0)
	{
	}

	TransactionOutput::TransactionOutput(
		std::string recipient,
		float value,
		std::string parentTransactionId)
		: recipient(recipient),
		value(value),
		parentTransactionId(parentTransactionId)
	{
		std::stringstream streamBuffer;
		streamBuffer << recipient << value << parentTransactionId;

		std::string buffer = streamBuffer.str();
		id = sha256(buffer);
	}

	//Check if coin belongs to you
	bool TransactionOutput::IsMine(std::string publicKey)
	{
		bool mine = false;

		if (publicKey == recipient)
		{
			mine = true;
		}

		return mine;
	}
}

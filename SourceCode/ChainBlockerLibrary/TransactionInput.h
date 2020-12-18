#pragma once
#include <string>

#include "TransactionOutput.h"

namespace ChainBlocker
{
	class TransactionInput
	{
		public:
			// Reference to TransactionOutputs -> transactionId
			std::string transactionOutputId;
			// Contains the Unspent transaction output
			TransactionOutput transactionOutput;

			TransactionInput(std::string transactionOutputId);
	};
}
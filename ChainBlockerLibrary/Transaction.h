#pragma once
#include <memory>
#include <string>
#include <vector>

#include "TransactionInput.h"

namespace ChainBlocker
{
	class Transaction
	{
		public:
			// This Calculates the transaction hash (which will be used as its Id)
			std::string CalulateHash();
			int GetAmount();
			// this is also the hash of the transaction.
			std::string GetId();
			// senders address/public key.
			std::string GetSender();
			// Recipients address/public key.
			std::string GetRecipient();
			// this is to prevent anybody else from spending funds in our wallet.
			std::string GetSignature();
			bool VerifySignature();

			Transaction(
				std::string sender,
				std::string recipient,
				int amount,
				std::vector<TransactionInput> inputs);

		private:
			std::string transactionId;
			std::string sender;
			std::string recipient;
			int amount;
			std::string signature;
			std::vector<TransactionInput> inputs;
			std::vector<TransactionOutput> outputs;
			// a rough count of how many transactions have been generated. 
			static int sequence;

			void CreateSignature();
	};
}

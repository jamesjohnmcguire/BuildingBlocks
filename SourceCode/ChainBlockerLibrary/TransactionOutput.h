#pragma once
#include <string>

namespace ChainBlocker
{
	class TransactionOutput
	{
		public:
			std::string id;
			// PublicKey, also known as the new owner of these coins.
			std::string recipient;
			//the amount of coins they own
			float value;
			//the id of the transaction this output was created in
			std::string parentTransactionId;

			TransactionOutput();
			TransactionOutput(
				std::string recipient,
				float value,
				std::string parentTransactionId);

			//Check if coin belongs to you
			bool IsMine(std::string publicKey);
	};
}

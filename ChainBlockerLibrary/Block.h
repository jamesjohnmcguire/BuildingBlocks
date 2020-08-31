#include <cstdint>
#include <iostream>
#include <sstream>

using namespace std;

class Block
{
	public:
		string Hash;
		string PreviousHash;

		Block();
		Block(uint32_t indexIn, const string& dataIn);
		Block(
			uint32_t indexIn,
			const string& dataIn,
			const string& previousHash);

		string GetHash();
		void MineBlock(uint32_t difficulty);

	private:
		string data;
		string hash;
		uint32_t index;
		int64_t nonce;
		time_t workingTime;

		string CalculateHash() const;
};

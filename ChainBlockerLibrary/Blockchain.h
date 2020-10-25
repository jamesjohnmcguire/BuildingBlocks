#pragma once
#include <cstdint>
#include <vector>
#include "Block.h"

using namespace std;

class Blockchain
{
	public:
		DllExport Blockchain();

		DllExport void AddBlock(Block newBlock);
		DllExport void SaveBlock(Block block);
		DllExport bool ValidateChain();

	private:
		uint32_t difficulty;
		vector<Block> chain;

		Block GetLastBlock() const;
};

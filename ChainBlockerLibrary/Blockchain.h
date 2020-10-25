#pragma once
#include <cstdint>
#include <vector>
#include "Block.h"

namespace ChainBlocker
{
	class Blockchain
	{
	public:
		DllExport Blockchain();

		DllExport void AddBlock(Block newBlock);
		DllExport void SaveBlock(Block block);
		DllExport bool ValidateChain();

	private:
		uint32_t difficulty;
		std::vector<Block> chain;

		Block GetLastBlock() const;
	};
}

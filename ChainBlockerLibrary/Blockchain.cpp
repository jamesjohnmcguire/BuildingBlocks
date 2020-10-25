#include "pch.h"
#include "Blockchain.h"
#include "BlockFile.h"

namespace ChainBlocker
{
	Blockchain::Blockchain()
	{
		Block genesis = Block(0, "Genesis Block");

		chain.emplace_back(genesis);
		difficulty = 6;
		difficulty = 2;
	}

	void Blockchain::AddBlock(Block newBlock)
	{
		Block previous = GetLastBlock();
		string previousHash = previous.GetHash();
		newBlock.SetHash(previousHash);

		newBlock.MineBlock(difficulty);
		chain.push_back(newBlock);
	}

	void Blockchain::SaveBlock(Block block)
	{
		string name = block.GetName();
		BlockFile file = BlockFile(name);
		file.Write(block);
	}

	bool Blockchain::ValidateChain()
	{
		string testPreviousHash;

		for (Block block : chain)
		{
			string testHash = block.CalculateHash();

			string blockHash = block.GetHash();
			string previousHash = block.GetPreviousHash();

			if ((testHash != blockHash) ||
				(testPreviousHash != previousHash))
			{
				return false;
			}
		}

		return true;
	}

	Block Blockchain::GetLastBlock() const
	{
		return chain.back();
	}
}

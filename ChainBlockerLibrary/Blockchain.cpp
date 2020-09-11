#include "pch.h"

#include "Blockchain.h"
#include "BlockFile.h"

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
	string previousHash = previous.Hash;
	newBlock.PreviousHash = previousHash;

	newBlock.MineBlock(difficulty);
	chain.push_back(newBlock);
}

void Blockchain::SaveBlock(Block block)
{
	BlockFile file = BlockFile(block.Name);
	file.Write(block);
}

bool Blockchain::ValidateChain()
{
	string testPreviousHash;

	for (Block block : chain)
	{
		string testHash = block.CalculateHash();

		if ((testHash != block.Hash) ||
			(testPreviousHash != block.PreviousHash))
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

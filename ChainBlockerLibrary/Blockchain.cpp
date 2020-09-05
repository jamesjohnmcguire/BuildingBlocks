#include "pch.h"

#include "Blockchain.h"
#include "BlockFile.h"

Blockchain::Blockchain()
{
	Block genesis = Block(0, "Genesis Block");

	chain.emplace_back(genesis);
	difficulty = 6;
	difficulty = 4;
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

Block Blockchain::GetLastBlock() const
{
	return chain.back();
}

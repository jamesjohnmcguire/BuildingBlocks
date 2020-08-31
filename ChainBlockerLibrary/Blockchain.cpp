#include "pch.h"

#include "Blockchain.h"

Blockchain::Blockchain()
{
	Block genesis = Block(0, "Genesis Block");

	chain.emplace_back(genesis);
	difficulty = 6;
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

}

Block Blockchain::GetLastBlock() const
{
	return chain.back();
}

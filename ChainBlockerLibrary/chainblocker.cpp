#include "pch.h"

#include <iostream>

#include "chainblocker.h"
#include "blockchain.h"
#include "wallet.h"

void Testing()
{
	cout << "Getting wallet..." << endl;
	Wallet wallet = Wallet();

	cout << "Starting mining..." << endl;

	Blockchain blockChain = Blockchain();

	cout << "Mining block 1..." << endl;
	Block block = Block(1, "Block 1 Data");
	blockChain.AddBlock(block);

	cout << "Saving block 1..." << endl;
	blockChain.SaveBlock(block);

	cout << "Mining block 2..." << endl;
	block = Block(2, "Block 2 Data");
	blockChain.AddBlock(block);

	cout << "Mining block 3..." << endl;
	block = Block(3, "Block 3 Data");
	blockChain.AddBlock(block);
}

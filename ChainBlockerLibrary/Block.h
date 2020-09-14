#pragma once
#include <cstdint>
#include<ctime>
#include <iostream>
#include <sstream>
#include "chainblocker.h"

using namespace std;

class DllExport Block
{
	public:
		string Hash;
		string Name;
		string PreviousHash;

		Block();
		Block(
			uint32_t indexIn,
			const string& dataIn);
		Block(
			uint32_t indexIn,
			const string& dataIn,
			const string& previousHash);

		string CalculateHash() const;
		string GetHash();
		time_t GetTimeStamp();
		void MineBlock(uint32_t difficulty);

	private:
		string data;
		string hash;
		uint32_t index;
		int64_t nonce;
		time_t timeStamp;
};

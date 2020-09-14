#pragma once
#include <cstdint>
#include<ctime>
#include <iostream>
#include <sstream>
#include "chainblocker.h"

using namespace std;

class Block
{
	public:
		string Hash;
		string Name;
		string PreviousHash;

		DllExport Block();
		DllExport Block(
			uint32_t indexIn,
			const string& dataIn);
		DllExport Block(
			uint32_t indexIn,
			const string& dataIn,
			const string& previousHash);

		DllExport string CalculateHash() const;
		DllExport string GetHash();
		DllExport time_t GetTimeStamp();
		DllExport void MineBlock(uint32_t difficulty);

	private:
		string data;
		string hash;
		uint32_t index;
		int64_t nonce;
		time_t timeStamp;
};

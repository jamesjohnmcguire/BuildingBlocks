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
		DllExport Block();
		DllExport Block(
			uint32_t indexIn,
			const string& dataIn);
		DllExport Block(
			uint32_t indexIn,
			const string& dataIn,
			const string& previousHash);

		DllExport string CalculateHash() const;
		DllExport string GetHash() const;
		DllExport string GetName() const;
		DllExport string GetPreviousHash() const;
		DllExport time_t GetTimeStamp() const;
		DllExport void MineBlock(uint32_t difficulty);
		DllExport void SetHash(string hash);

	private:
		string data;
		string hash;
		uint32_t index;
		string name;
		int64_t nonce;
		string previousHash;
		time_t timeStamp;
};

#pragma once
#include <cstdint>
#include<ctime>
#include <iostream>
#include <sstream>
#include "chainblocker.h"

class Block
{
	public:
		DllExport Block();
		DllExport Block(
			uint32_t indexIn,
			const std::string& dataIn);
		DllExport Block(
			uint32_t indexIn,
			const std::string& dataIn,
			const std::string& previousHash);

		DllExport std::string CalculateHash() const;
		DllExport std::string GetHash() const;
		DllExport std::string GetName() const;
		DllExport std::string GetPreviousHash() const;
		DllExport time_t GetTimeStamp() const;
		DllExport void MineBlock(uint32_t difficulty);
		DllExport void SetHash(std::string hash);

	private:
		std::string data;
		std::string hash;
		uint32_t index;
		std::string name;
		int64_t nonce;
		std::string previousHash;
		time_t timeStamp;
};

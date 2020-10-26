#include "pch.h"

#include <time.h>
#include <vector>

#include "sha256.h"
#include "Block.h"

namespace ChainBlocker
{
	Block::Block()
	{
		index = 0;
		nonce = -1;

		timeStamp = time(nullptr);
	}

	Block::Block(const Block& other)
	{
		data = other.data;
		hash = other.hash;
		index = other.index;
		name = other.name;
		nonce = other.nonce;
		previousHash = other.previousHash;
		timeStamp = other.timeStamp;
	}

	Block::Block(uint32_t indexIn, const std::string& dataIn)
		: index(indexIn), data(dataIn), name(dataIn)
	{
		nonce = -1;
		timeStamp = time(nullptr);
	}

	Block::Block(
		uint32_t indexIn, const std::string& dataIn, const std::string& previousHash)
		: index(indexIn), data(dataIn), name(dataIn), previousHash(previousHash)
	{
		nonce = -1;
		timeStamp = time(nullptr);
	}

	inline std::string Block::CalculateHash() const
	{
		std::stringstream streamBuffer;
		streamBuffer << index << timeStamp << data << nonce << previousHash;

		std::string buffer = streamBuffer.str();
		std::string hash = sha256(buffer);
		return hash;
	}

	std::string Block::GetHash() const
	{
		return hash;
	}

	std::string Block::GetName() const
	{
		return name;
	}

	std::string Block::GetPreviousHash() const
	{
		return previousHash;
	}

	time_t Block::GetTimeStamp() const
	{
		return timeStamp;
	}

	void Block::MineBlock(uint32_t difficulty)
	{
		time_t start, end;
		time(&start);

		size_t size = (size_t)difficulty;
		std::vector<char> tempBuffer(size);

		for (uint32_t i = 0; i < difficulty; ++i)
		{
			tempBuffer[i] = '0';
		}

		std::string testBuffer(tempBuffer.begin(), tempBuffer.end());
		std::string testHash;

		do
		{
			nonce++;
			hash = CalculateHash();
			testHash = hash.substr(0, difficulty);
		} while (testHash != testBuffer);

		time(&end);
		double diff = difftime(end, start);
		int totalSeconds = (int)diff;

		int minutes = totalSeconds / 60;
		int hours = minutes / 60;
		int minutesRemainder = minutes % 60;
		int secondsRemainder = totalSeconds % 60;

		std::cout << "Block mined: " << hash << std::endl;
		std::cout << "Time taken: " << hours << ":" << minutesRemainder << ":" <<
			secondsRemainder << std::endl;
	}

	void Block::SetHash(std::string hash)
	{
		this->hash = hash;
	}
}
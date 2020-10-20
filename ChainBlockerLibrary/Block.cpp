#include "pch.h"

#include "Block.h"
#include "sha256.h"
#include <time.h>
#include <vector>

Block::Block()
{
	index = 0;
	nonce = -1;

	timeStamp = time(nullptr);
}

Block::Block(uint32_t indexIn, const string& dataIn)
	: index(indexIn), data(dataIn), name(dataIn)
{
	nonce = -1;
	timeStamp = time(nullptr);
}

Block::Block(
	uint32_t indexIn, const string& dataIn, const string& previousHash)
	: index(indexIn), data(dataIn), name(dataIn), previousHash(previousHash)
{
	nonce = -1;
	timeStamp = time(nullptr);
}

inline string Block::CalculateHash() const
{
	stringstream streamBuffer;
	streamBuffer << index << timeStamp << data << nonce << previousHash;

	string buffer = streamBuffer.str();
	string hash = sha256(buffer);
	return hash;
}

string Block::GetHash() const
{
	return hash;
}

string Block::GetName() const
{
	return name;
}

string Block::GetPreviousHash() const
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
	vector<char> tempBuffer(size);

	for (uint32_t i = 0; i < difficulty; ++i)
	{
		tempBuffer[i] = '0';
	}

	string testBuffer(tempBuffer.begin(), tempBuffer.end());
	string testHash;

	do
	{
		nonce++;
		hash = CalculateHash();
		testHash = hash.substr(0, difficulty);
	}
	while (testHash != testBuffer);

	time(&end);
	double diff = difftime(end, start);
	int totalSeconds = (int)diff;

	int minutes = totalSeconds / 60;
	int hours = minutes / 60;
	int minutesRemainder = minutes % 60;
	int secondsRemainder = totalSeconds % 60;

	cout << "Block mined: " << hash << endl;
	cout << "Time taken: " << hours << ":" << minutesRemainder << ":" << secondsRemainder << endl;
}

void Block::SetHash(string hash)
{
	this->hash = hash;
}

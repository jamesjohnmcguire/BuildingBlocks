#include "pch.h"

#include "Block.h"
#include "sha256.h"
#include <time.h>
#include <vector>

Block::Block()
{
	index = 0;
	nonce = -1;

	TimeStamp = time(nullptr);
}

Block::Block(uint32_t indexIn, const string& dataIn)
	: index(indexIn), data(dataIn), Name(dataIn)
{
	nonce = -1;
	TimeStamp = time(nullptr);
}

Block::Block(
	uint32_t indexIn, const string& dataIn, const string& previousHash)
	: index(indexIn), data(dataIn), Name(dataIn), PreviousHash(previousHash)
{
	nonce = -1;
	TimeStamp = time(nullptr);
}

string Block::GetHash()
{
	return hash;
}

void Block::MineBlock(uint32_t difficulty)
{
	time_t start, end;
	time(&start);

	size_t size = (size_t)difficulty + 1;
	vector<char> tempBuffer(size);

	for (uint32_t i = 0; i < difficulty; ++i)
	{
		tempBuffer[i] = '0';
	}
	tempBuffer[difficulty] = '\0';

	string testBuffer(tempBuffer.begin(), tempBuffer.end());
	string testHash;

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

	cout << "Block mined: " << hash << endl;
	cout << "Time taken: " << hours << ":" << minutesRemainder << ":" << secondsRemainder << endl;
}

inline string Block::CalculateHash() const
{
	stringstream streamBuffer;
	streamBuffer << index << TimeStamp << data << nonce << PreviousHash;

	string buffer = streamBuffer.str();
	string hash =  sha256(buffer);
	return hash;
}

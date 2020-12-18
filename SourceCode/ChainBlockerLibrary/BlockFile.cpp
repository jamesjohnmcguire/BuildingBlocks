#include "pch.h"
#include "BlockFile.h"

namespace ChainBlocker
{
	BlockFile::BlockFile(std::string fileName)
		: fileName(fileName)
	{
	}

	BlockFile::BlockFile(const BlockFile& other)
	{
	}

	void BlockFile::Write(Block block)
	{
		std::fstream file;
		file.open(fileName, std::ios::binary | std::ios::out);

		if (file)
		{
			size_t size = sizeof(block);
			file.write((char*)&block, size);
		}

		file.close();
	}

	Block BlockFile::Read()
	{
		Block block;
		std::fstream file;

		file.open(fileName, std::ios::binary | std::ios::in);

		if (file)
		{
			// block.read(File);
		}

		file.close();

		return block;
	}
}

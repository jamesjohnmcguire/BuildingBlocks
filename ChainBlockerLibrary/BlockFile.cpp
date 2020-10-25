#include "pch.h"
#include "BlockFile.h"

namespace ChainBlocker
{
	BlockFile::BlockFile(string fileName)
		: FileName(fileName)
	{

	}

	void BlockFile::Write(Block block)
	{
		File.open(FileName, std::ios::binary | std::ios::out);

		if (File)
		{
			size_t size = sizeof(block);
			File.write((char*)&block, size);
		}

		File.close();
	}

	Block BlockFile::Read()
	{
		Block block;

		File.open(FileName, std::ios::binary | std::ios::in);

		if (File)
		{
			// block.read(File);
		}

		File.close();
		return block;
	}
}

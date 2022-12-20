#pragma once

#include <fstream>
#include <string>

#include "Block.h"

namespace ChainBlocker
{
	class BlockFile
	{
		public:
			DllExport BlockFile(std::string FileName);
			DllExport BlockFile(const BlockFile& other);
			~BlockFile() = default;

			DllExport Block Read();
			DllExport void Write(Block block);

		private:
			std::string fileName;
	};
}

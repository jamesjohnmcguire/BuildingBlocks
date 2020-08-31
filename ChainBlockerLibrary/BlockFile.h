#pragma once
#include <fstream>
#include <string>
#include "Block.h"

class BlockFile
{
    private:
        std::string FileName;
        std::fstream File;

    public:
        BlockFile(std::string FileName);
        void Write(Block block);
        Block Read();
};

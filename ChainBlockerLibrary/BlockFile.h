#pragma once

#include <fstream>
#include <string>
#include "Block.h"

using namespace std;

class BlockFile
{
    private:
        std::string FileName;
        std::fstream File;

    public:
        BlockFile(string FileName);
        void Write(Block block);
        Block Read();
};

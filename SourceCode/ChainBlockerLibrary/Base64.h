#pragma once
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "chainblocker.h"

namespace ChainBlocker
{
	class Base64
	{
		public:
			DllExport static std::vector<unsigned char> Decode(
				std::string input,
				size_t length,
				size_t* outputLength);
			DllExport static std::vector<char> Encode(
				const unsigned char* input,
				size_t length);
	};
}

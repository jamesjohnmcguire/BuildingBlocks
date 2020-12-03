#pragma once
#include <memory>
#include <string>

#include <openssl/evp.h>

#include "chainblocker.h"
#include "OpenSslPointers.h"

namespace ChainBlocker
{
	class Base64
	{
		public:
			DllExport static std::unique_ptr<unsigned char> Decode(
				std::string input,
				size_t length,
				size_t* outputLength);
			DllExport static std::unique_ptr<char> Encode(
				const unsigned char* input,
				size_t length);
	};
}

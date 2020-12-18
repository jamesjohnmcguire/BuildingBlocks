#include "pch.h"

#include "Base64.h"

namespace ChainBlocker
{
	std::vector<unsigned char> Base64::Decode(
		std::string input, size_t inputLength, size_t* outputLength)
	{
		std::vector<unsigned char> output;

		const unsigned char* inputBuffer =
			reinterpret_cast<const unsigned char*>(input.c_str());

		const size_t bufferLength = 3 * inputLength / 4;

		unsigned char* rawBuffer =
			reinterpret_cast<unsigned char*>(calloc(bufferLength, 1));

		int inputBufferLength = static_cast<int>(inputLength);
		int actualLength =
			EVP_DecodeBlock(rawBuffer, inputBuffer, inputBufferLength);

		if (actualLength > -1)
		{
			if (actualLength != bufferLength)
			{
				// log warning
			}

			size_t last = inputLength - 1;
			while (input[last] == '=')
			{
				actualLength--;
				last--;
			}

			*outputLength = actualLength;

			output = std::vector<unsigned char>(
				rawBuffer, rawBuffer + actualLength);
		}

		return output;
	}

	std::vector<char> Base64::Encode(
		const unsigned char* input, size_t inputLength)
	{
		std::vector<char> output;

		size_t encodeLength = 4 * ((inputLength + 2) / 3);

		// +1 for the terminating null
		encodeLength = encodeLength + 1;

		void* buffer = calloc(encodeLength, 1);
		char* charBuffer = reinterpret_cast<char*>(buffer);

		unsigned char* encodeBuffer =
			reinterpret_cast<unsigned char*>(charBuffer);

		int bufferLength = static_cast<int>(inputLength);
		int outputLength =
			EVP_EncodeBlock(encodeBuffer, input, bufferLength);

		if (outputLength > -1)
		{
			if (encodeLength != outputLength)
			{
				// log warning
			}

			output = std::vector<char>(charBuffer, charBuffer + outputLength);
		}

		return output;
	}
}
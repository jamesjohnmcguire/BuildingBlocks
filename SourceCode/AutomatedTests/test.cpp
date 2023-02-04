#pragma warning(disable: 26495)
#pragma warning(disable: 26812)

#include "pch.h"

#include <algorithm>
#include <regex>

#include "../ChainBlockerLibrary/chainblocker.h"
#include "../ChainBlockerLibrary/Base64.h"
#include "../ChainBlockerLibrary/Block.h"
#include "../ChainBlockerLibrary/Cryptography.h"
#include "../ChainBlockerLibrary/CryptographicKey.h"

using namespace ChainBlocker;

std::string latinText = "Lorem ipsum dolor sit amet, consectetur "\
	"adipiscing elit. Curabitur eget augue dolor. Suspendisse non dapibus "\
	"enim, at convallis ipsum. Nulla vehicula eu ligula nec egestas. Nunc "\
	"nec est id felis semper consectetur. Nulla facilisi. In viverra ex at "\
	"erat scelerisque, id tincidunt dui commodo. In dictum quis ipsum et "\
	"aliquam. Duis urna justo, mollis quis pulvinar quis, vestibulum vel "\
	"arcu. Nam id gravida augue. Duis accumsan maximus congue. Donec sed "\
	"egestas risus. Suspendisse suscipit elit sit amet leo malesuada, nec "\
	"auctor velit vulputate. Morbi hendrerit tincidunt ligula, at auctor "\
	"sem scelerisque iaculis. Phasellus ultricies elit nibh, vitae consequat "\
	"lacus convallis vitae. Proin fringilla molestie sapien id pretium. "\
	"Nullam condimentum mi vitae consequat malesuada.\n";

std::string privateKey = "-----BEGIN RSA PRIVATE KEY-----\n"\
	"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
	"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
	"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
	"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
	"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
	"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
	"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
	"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
	"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
	"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
	"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
	"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
	"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
	"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
	"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
	"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
	"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
	"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
	"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
	"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
	"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
	"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
	"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
	"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
	"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
	"-----END RSA PRIVATE KEY-----\n\0";

std::string publicKey = "-----BEGIN PUBLIC KEY-----\n"\
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
	"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
	"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
	"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
	"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
	"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
	"wQIDAQAB\n"\
	"-----END PUBLIC KEY-----\n";

TEST(TestCaseName, TestName)
{
  EXPECT_EQ(1, 1);
  EXPECT_TRUE(true);
}

TEST(BlockInitialization, SimpleBlock)
{
	Block block = Block();

	time_t timeStamp = block.GetTimeStamp();

	EXPECT_TRUE(timeStamp > 0);
}

TEST(Base64, EncodeDecodeAscii)
{
	std::string text = "Lorem ipsum dolor sit amet, consectetur "\
		"adipiscing elit. Curabitur eget augue dolor. Suspendisse non dapibus "\
		"enim, at convallis ipsum. Nulla vehicula eu ligula nec egestas. Nunc "\
		"nec est id felis semper consectetur. Nulla facilisi. In viverra ex at "\
		"erat scelerisque, id tincidunt dui commodo. In dictum quis ipsum et "\
		"aliquam. Duis urna justo, mollis quis pulvinar quis, vestibulum vel ";

	std::vector<char> encoded = Base64::Encode(
		(unsigned char*)text.c_str(), text.length());

	char* buffer = encoded.data();
	size_t size = encoded.size();
	size_t outputSize;

	std::vector<unsigned char> decoded = Base64::Decode(
		buffer, size, &outputSize);

	buffer = (char*)decoded.data();

	std::string decodedText(buffer, 0, outputSize);

	int result = text.compare(decodedText);

	ASSERT_EQ(result, 0);
}


TEST(Base64, EncodeDecodeAsciiLoop)
{
	size_t length = latinText.length();

	for (size_t index = 1; index < length; index++)
	{
		std::string temp = latinText.substr(0, index);

		std::vector<char> encoded = Base64::Encode(
			(unsigned char*)temp.c_str(), temp.length());

		char* buffer = encoded.data();
		size_t size = encoded.size();
		size_t outputSize;

		std::vector<unsigned char> decoded = Base64::Decode(
			buffer, size, &outputSize);

		buffer = (char*)decoded.data();

		int result = temp.compare(0, index, buffer, 0, index);

		ASSERT_EQ(result, 0);
	}
}

TEST(Base64, EncodeDecodeAsciiNewLine)
{
	std::string text = "Lorem ipsum dolor sit amet, consectetur\n";

	std::vector<char> encoded = Base64::Encode(
		(unsigned char*)text.c_str(), text.length());

	char* buffer = encoded.data();
	size_t size = encoded.size();
	size_t outputSize;

	std::vector<unsigned char> decoded = Base64::Decode(
		buffer, size, &outputSize);

	buffer = (char*)decoded.data();

	int result = text.compare(0, outputSize, buffer, 0, outputSize);

	ASSERT_EQ(result, 0);
}

TEST(Cryptography, CreateEvpKey)
{
	Cryptography cryptography = Cryptography();
	EvpKeyPointer result = cryptography.CreateEvpKey();

	EXPECT_NE(result, nullptr);
}

TEST(Cryptography, SignData)
{
	std::string plainText = "My secret message.\n";

	Cryptography cryptography = Cryptography();

	std::vector<char> signature =
		cryptography.SignData(privateKey, plainText);

	std::string data = std::string(signature.data(), signature.size());

	bool authentic =
		cryptography.VerifySignature(publicKey, plainText, data);

	ASSERT_TRUE(authentic);
}

TEST(Cryptography, PEMFormat)
{
	CryptographicKey key = CryptographicKey(AlgorythmType::Rsa);
	std::string pem = key.GetPublicKeyPem(PemFormatType::Pkcs1Rsa);

	std::string expression = "-+BEGIN[a-zA-Z ]*-+\\n"\
		"[A-Za-z0-9/\\n+]+"\
		"-+END[a-zA-Z ]*-+\\n";

	std::regex regexExpression(expression);

	bool matched = std::regex_match(pem, regexExpression);

	ASSERT_TRUE(matched);
}

TEST(Cryptography, PublicKeyDerivation)
{
	// Create public key from private key
	CryptographicKey cryptographicKey = CryptographicKey(privateKey);

	std::string newPublicKey = cryptographicKey.GetPublicKeyPem(
		PemFormatType::SubjectPublicKeyInfo);

	int result = publicKey.compare(newPublicKey);

	ASSERT_EQ(result, 0);
}

TEST(CryptographyKey, Success)
{
	std::unique_ptr<CryptographicKey> key =
		CryptographicKey::Create(AlgorythmType::Rsa);

	EXPECT_NE(key, nullptr);
}

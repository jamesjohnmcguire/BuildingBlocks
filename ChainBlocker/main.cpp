// ChainBlocker.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <regex>

#include "../ChainBlockerLibrary/Blockchain.h"
#include "../ChainBlockerLibrary/Cryptography.h"
#include "../ChainBlockerLibrary/Transaction.h"
#include "../ChainBlockerLibrary/Wallet.h"

#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

using namespace ChainBlocker;

void Test();

int main()
{
	std::cout << "Starting application\n";
	Test();

#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif
}

void Test()
{
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

	Testing();

	std::cout << "Testing message signing..." << std::endl;
	Cryptography cryptography = Cryptography();

	std::string plainText = "My secret message.\n";

	std::cout << "Signing message..." << std::endl;
	std::vector<char> signature =
		cryptography.SignData(privateKey, plainText);

	std::string data = std::string(signature.data(), signature.size());
	bool authentic = cryptography.VerifySignature(
		publicKey, "My secret message.\n", data);

	if (authentic)
	{
		std::cout << "Signed data verified" << std::endl;
	}
	else
	{
		std::cout << "Signed data NOT verified" << std::endl;
	}

	CryptographicKey key = CryptographicKey(AlgorythmType::Rsa);
	std::string pem = key.GetPublicKeyPem();

	std::string expression = "-+BEGIN[a-zA-Z ]*-+\\n"\
		"[A-Za-z0-9/\\n+]+"\
		"-+END[a-zA-Z ]*-+\\n";

	std::regex regexExpression(expression);

	if (std::regex_match(pem, regexExpression))
	{
		std::cout << "PEM format verified" << std::endl;
	}
	else
	{
		std::cout << "PEM format NOT verified" << std::endl;
	}

	//////////////////////////////////////////////////////////////////////
	std::cout << "Getting wallet..." << std::endl;
	Wallet walletSender = Wallet();
	std::string senderPublicKey = walletSender.GetPublicKeyPem();

	Wallet walletRecipient = Wallet();
	std::string recipientPublicKey = walletRecipient.GetPublicKeyPem();

	std::cout << "Creating transation..." << std::endl;
	std::vector<TransactionInput> inputs = std::vector<TransactionInput>();

	Transaction transaction = Transaction(
		senderPublicKey, recipientPublicKey, 5, inputs);
	transaction.VerifySignature();

	//////////////////////////////////////////////////////////////////////
	std::cout << "Starting mining..." << std::endl;

	Blockchain blockChain = Blockchain();

	std::cout << "Mining block 1..." << std::endl;
	Block block = Block(1, "Block 1 Data");
	blockChain.AddBlock(block);

	std::cout << "Saving block 1..." << std::endl;
	blockChain.SaveBlock(block);

	std::cout << "Mining block 2..." << std::endl;
	block = Block(2, "Block 2 Data");
	blockChain.AddBlock(block);

	std::cout << "Mining block 3..." << std::endl;
	block = Block(3, "Block 3 Data");
	blockChain.AddBlock(block);
}

#pragma warning(disable: 26495)
#pragma warning(disable: 26812)
#include "pch.h"

#include "../ChainBlockerLibrary/chainblocker.h"
#include "../ChainBlockerLibrary/Block.h"

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

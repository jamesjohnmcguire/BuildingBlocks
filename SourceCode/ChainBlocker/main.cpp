// ChainBlocker.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include "../ChainBlockerLibrary/chainblocker.h"

int main()
{
	std::cout << "Starting application\n";
	Testing();

#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif
}

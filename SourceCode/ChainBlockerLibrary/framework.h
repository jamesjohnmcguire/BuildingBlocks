#pragma once

#if defined _WIN32 || defined __CYGWIN__
	// Exclude rarely-used stuff from Windows headers
	#define WIN32_LEAN_AND_MEAN
	#include <windows.h>
#endif

#pragma once

// Exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define DEF_EXPORT __declspec(dllexport)
#define DllExport	__declspec( dllexport )

extern "C" void DllExport WINAPI Testing();

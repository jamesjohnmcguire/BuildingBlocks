#pragma once

#if defined _WIN32 || defined __CYGWIN__
	#ifdef DLL_EXPORTS
		#if defined WIN32
			#define LIB_API(RetType) extern "C" __declspec(dllexport) RetType
		#else
			#define LIB_API(RetType) extern "C" RetType __attribute__((visibility("default")))
		#endif

		#ifdef __GNUC__
			#define EXPORT_API extern "C" __attribute__ ((dllexport))
		#else
			// Note: actually gcc seems to also supports this syntax.
			#define EXPORT_API extern "C" __declspec (dllexport)
		#endif
	#else
		#if defined WIN32
			#define LIB_API(RetType) extern "C" __declspec(dllimport) RetType
		#else
			#define LIB_API(RetType) extern "C" RetType
		#endif

		#ifdef __GNUC__
			#define EXPORT_API extern "C" __attribute__ ((dllimport))
		#else
			#define EXPORT_API extern "C" __declspec (dllimport)
		#endif
	#endif
#else
	#if __GNUC__ >= 4
		#define EXPORT_API extern "C" __attribute__ ((visibility ("default")))
	#else
		#define EXPORT_API
	#endif
#endif

LIB_API(void) Testing();

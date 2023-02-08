cmake_minimum_required (VERSION 3.8)

include (GenerateExportHeader)

add_compile_definitions(DLL_EXPORTS)

find_package(OpenSSL REQUIRED)

IF (WIN32)
	MESSAGE( STATUS "Building for WIN32" )

	add_library (ChainBlockerLibrary SHARED "chainblocker.cpp" "chainblocker.h" "Block.h" "Block.cpp" "Blockchain.h" "Blockchain.cpp" "BlockFile.h" "BlockFile.cpp" "CryptographicKeyPair.h" "Cryptography.h" "Cryptography.cpp" "sha256.h" "sha256.cpp" "Wallet.h" "Wallet.cpp" "dllmain.cpp" "framework.h" "pch.h" "pch.cpp")
ELSE()
	add_library (ChainBlockerLibrary SHARED "chainblocker.cpp" "chainblocker.h" "Block.h" "Block.cpp" "Blockchain.h" "Blockchain.cpp" "BlockFile.h" "BlockFile.cpp" "CryptographicKeyPair.h" "Cryptography.h" "Cryptography.cpp" "sha256.h" "sha256.cpp" "Wallet.h" "Wallet.cpp")
ENDIF()

target_link_libraries(ChainBlockerLibrary PRIVATE OpenSSL::SSL OpenSSL::Crypto)

GENERATE_EXPORT_HEADER( ChainBlockerLibrary
             BASE_NAME ChainBlockerLibrary
             EXPORT_MACRO_NAME ChainBlockerLibrary_EXPORT
             EXPORT_FILE_NAME ChainBlockerLibrary_Export.h
             STATIC_DEFINE ChainBlockerLibrary_BUILT_AS_STATIC
)

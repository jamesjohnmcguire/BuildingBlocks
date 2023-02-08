cmake_minimum_required (VERSION 3.8)

project ("ChainBlocker" LANGUAGES CXX)

add_executable (ChainBlocker "main.cpp")

target_link_libraries (ChainBlocker ChainBlockerLibrary)

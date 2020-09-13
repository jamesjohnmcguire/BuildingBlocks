# CMakeList.txt : CMake project for ChainBlock, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (ChainBlocker "main.cpp")

target_link_libraries (ChainBlocker ChainBlockerLibrary)

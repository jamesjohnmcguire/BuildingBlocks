﻿# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.16)

project ("BuildingBlocks" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

# Include sub-projects.
add_subdirectory ("AutomatedTests")
add_subdirectory ("ChainBlocker")
add_subdirectory ("ChainBlockerLibrary")

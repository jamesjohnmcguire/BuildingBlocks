set(BINARY AutomatedTests)

include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        release-1.11.0
)

FetchContent_MakeAvailable(googletest)
add_library(GTest::GTest INTERFACE IMPORTED)
target_link_libraries(GTest::GTest INTERFACE gtest_main)

add_compile_definitions(DLL_IMPORTS)

add_executable(AutomatedTests "pch.h" "pch.cpp" "test.cpp")

target_link_libraries(AutomatedTests PRIVATE GTest::GTest ChainBlockerLibrary)

add_test(NAME AutomatedTests COMMAND AutomatedTests)

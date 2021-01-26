set(BINARY AutomatedTests)

add_executable(AutomatedTests "pch.h" "pch.cpp" "test.cpp")

add_test(NAME AutomatedTests COMMAND AutomatedTests)

target_link_libraries(AutomatedTests PUBLIC AutomatedTests gtest)

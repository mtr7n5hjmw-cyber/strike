cmake_minimum_required(VERSION 3.20)
project(StrikeMenuHelper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(StrikeMenuHelper WIN32
    Hwid.cpp
    StrikeMenuHelper.cpp
)

target_link_libraries(StrikeMenuHelper PRIVATE
    bcrypt
    winhttp
    ws2_32
)
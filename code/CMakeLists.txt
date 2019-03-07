cmake_minimum_required(VERSION 2.8)
include_directories($ENV{MBEDTLS}/include)
link_directories($ENV{MBEDTLS}/debug)
project(cryptograpy)
set(sources main.cpp
	Cryptographer.cpp)
add_executable(${PROJECT_NAME} ${sources})
target_link_libraries(${PROJECT_NAME} mbedcrypto)

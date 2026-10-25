cmake_minimum_required(VERSION 3.20)
project(sefs C)

find_package(OpenSSL REQUIRED)

file(GLOB SRC src/*.c)
add_library(sefs SHARED ${SRC})
target_compile_definitions(sefs PRIVATE SEFS_EXPORTS _CRT_SECURE_NO_WARNINGS)
target_link_libraries(sefs PRIVATE OpenSSL::Crypto)
if(MSVC)
  target_compile_options(sefs PRIVATE /W4)
endif()

add_executable(keygen tools/keygen.c)
target_compile_definitions(keygen PRIVATE _CRT_SECURE_NO_WARNINGS)
target_link_libraries(keygen PRIVATE OpenSSL::Crypto)

option(SEFS_ASAN "Build with AddressSanitizer" OFF)
if(SEFS_ASAN)
  target_compile_options(sefs PRIVATE /fsanitize=address /Zi)
endif()

cmake_minimum_required(VERSION 3.7)
project(embedtls_sha256)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c)
add_executable(embedtls_sha256 ${SOURCE_FILES})
target_link_libraries(embedtls_sha256 mbedcrypto)

add_executable(ecdsa gen_key.c)
target_link_libraries(ecdsa mbedcrypto)
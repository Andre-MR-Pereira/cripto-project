# cmake_minimum_required(VERSION <specify CMake version here>)
cmake_minimum_required(VERSION 3.12)
project(cripto_project)
find_package(SEAL 3.6.0 EXACT REQUIRED)

set(CMAKE_CXX_STANDARD 14)

add_executable(cripto_project main.cpp lib/assets/examples/test/test_run.cpp lib/assets/encryptions/database_encryption.cpp)

target_link_libraries(cripto_project SEAL::seal)
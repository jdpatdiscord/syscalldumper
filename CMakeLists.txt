cmake_minimum_required(VERSION 3.15)

PROJECT(SyscallDumper LANGUAGES CXX)

add_executable(SyscallDumper_Exe program.cpp)

add_subdirectory(zydis/)

target_compile_options(SyscallDumper_Exe PUBLIC -O0 -g3)

target_include_directories(SyscallDumper_Exe PUBLIC zydis/include)
target_link_directories(SyscallDumper_Exe PUBLIC build/zydis)
target_link_libraries(SyscallDumper_Exe PUBLIC Zydis)
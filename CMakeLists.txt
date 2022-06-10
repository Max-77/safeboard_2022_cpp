cmake_minimum_required(VERSION 3.21)
project(safeboard_cpp_step2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static -fopenmp")
add_executable(scan_util main.cpp scan_js.h scan_bat.h scan_exe.h return_codes.h)

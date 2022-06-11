cmake_minimum_required(VERSION 3.21)
project(safeboard_cpp_step2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static -fopenmp")
add_executable(scan_util main.cpp modules/js_scanner/scan_js.h modules/bat_scanner/scan_bat.h modules/exe_scanner/scan_exe.h modules/helpers/return_codes.h modules/js_scanner/scan_js.cpp modules/bat_scanner/scan_bat.cpp modules/exe_scanner/scan_exe.cpp modules/helpers/get_signatures.cpp modules/helpers/get_signatures.h)

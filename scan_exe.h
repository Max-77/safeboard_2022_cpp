#include <cstring>
#include <fstream>
#include <iostream>
#include "return_codes.h"

#ifndef SAFEBOARD_CPP_STEP2_SCAN_EXE_H
#define SAFEBOARD_CPP_STEP2_SCAN_EXE_H

#define suspicious_exe_string_1 "CreateRemoteThread"
#define suspicious_exe_string_2 "CreateProcess"


bool scan_exe(std::string filepath){
    int result_of_scanning = not_suspicious_file;

    // try to open file
    std::ifstream exe_file(filepath);

    // if smth wrong -> return error code
    if (exe_file.fail())
        return error_code;

    // get size of file in bytes
    exe_file.seekg(0, std::ios::end);
    size_t size_of_file = exe_file.tellg();

    // allocate memory to store file in
    char *buf = new char[size_of_file];

    // reading file into buffer
    exe_file.seekg(0, std::ios::beg);
    exe_file.read(buf, size_of_file);
    exe_file.close();

    // move buf to string
    std::string str_file;
    str_file.assign (buf, size_of_file);

    delete [] buf;

    // searching for 1 of suspicious strings
    if ((int)str_file.find(suspicious_exe_string_1) >= 0 || (int)str_file.find(suspicious_exe_string_2) >= 0){
        result_of_scanning = suspicious_file;
    }

    return result_of_scanning;
}

#endif //SAFEBOARD_CPP_STEP2_SCAN_EXE_H

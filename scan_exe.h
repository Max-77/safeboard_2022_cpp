#include <cstring>
#include <fstream>
#include <iostream>
#include "return_codes.h"

#ifndef KASPER_CPP_STEP2_SCAN_EXE_H
#define KASPER_CPP_STEP2_SCAN_EXE_H

#define suspicious_exe_string_1 "CreateRemoteThread"
#define suspicious_exe_string_2 "CreateProcess"


bool scan_exe(std::string filepath){
    int result_of_scanning = not_suspicious_file;

    std::ifstream exe_file(filepath);

    if (exe_file.fail())
        return error_code;

    exe_file.seekg(0, std::ios::end);
    size_t size_of_file = exe_file.tellg();

    char *buf = new char[size_of_file];

    exe_file.seekg(0, std::ios::beg);
    exe_file.read(buf, size_of_file);
    exe_file.close();

    std::string str_file;
    str_file.assign (buf, size_of_file);

    delete [] buf;

    if ((int)str_file.find(suspicious_exe_string_1) >= 0 || (int)str_file.find(suspicious_exe_string_2) >= 0){
        result_of_scanning = suspicious_file;
    }

    return result_of_scanning;
}

#endif //KASPER_CPP_STEP2_SCAN_EXE_H

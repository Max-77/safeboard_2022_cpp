#include <cstring>
#include <fstream>
#include <iostream>
#include "return_codes.h"

#ifndef SAFEBOARD_CPP_STEP2_SCAN_BAT_H
#define SAFEBOARD_CPP_STEP2_SCAN_BAT_H

#define suspicious_bat_string "rd /s /q \"c:\\windows\""

int scan_bat(std::string filepath){

    int result_of_scanning = not_suspicious_file;

    // try to open file
    std::ifstream bat_file(filepath);

    // if smth wrong -> return error code
    if (bat_file.fail())
        return error_code;

    std::string tmp_string;

    // read file line by line while not found suspicious string, use getline() to read all lines, including spaces
    while (std::getline(bat_file, tmp_string) && result_of_scanning == not_suspicious_file){
        result_of_scanning = (tmp_string == suspicious_bat_string);
    }

    bat_file.close();

    return result_of_scanning;
}

#endif //SAFEBOARD_CPP_STEP2_SCAN_BAT_H

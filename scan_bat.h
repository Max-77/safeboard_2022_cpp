#include <cstring>
#include <fstream>
#include <iostream>
#include "return_codes.h"

#ifndef KASPER_CPP_STEP2_SCAN_BAT_H
#define KASPER_CPP_STEP2_SCAN_BAT_H

#define suspicious_bat_string "rd /s /q \"c:\\windows\""

int scan_bat(std::string filepath){

    int result_of_scanning = not_suspicious_file;

    std::ifstream bat_file(filepath);
    std::string tmp_string;

    if (bat_file.fail())
        return error_code;


    while (std::getline(bat_file, tmp_string) && result_of_scanning == not_suspicious_file){
        result_of_scanning = (tmp_string == suspicious_bat_string);
    }

    bat_file.close();

    return result_of_scanning;
}

#endif //KASPER_CPP_STEP2_SCAN_BAT_H

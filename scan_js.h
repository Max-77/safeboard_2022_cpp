#include <cstring>
#include <fstream>
#include <iostream>
#include "return_codes.h"

#ifndef KASPER_CPP_STEP2_SCAN_JS_H
#define KASPER_CPP_STEP2_SCAN_JS_H

#define suspicious_js_string "<script>evil_script()</script>"

int scan_js(std::string filepath){
    int result_of_scanning = not_suspicious_file;

    // try to open file
    std::ifstream js_file(filepath);

    // if smth wrong -> return error code
    if (js_file.fail())
        return error_code;

    std::string tmp_string;

    // read file line by line while not found suspicious string
    while (js_file >> tmp_string && result_of_scanning == not_suspicious_file){
        result_of_scanning = (tmp_string == suspicious_js_string);
    }

    js_file.close();

    return result_of_scanning;
}

#endif //KASPER_CPP_STEP2_SCAN_JS_H

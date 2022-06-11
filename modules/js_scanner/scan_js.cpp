#include "scan_js.h"

int scan_js(string filepath){
    vector <string> signatures = get_signatures("../modules/js_scanner/signatures");

    int result_of_scanning = not_suspicious_file;

    // try to open file
    ifstream js_file(filepath);

    // if smth wrong -> return error code
    if (js_file.fail())
        return error_code_;

    string tmp_string;

    // read file line by line while not found suspicious string
    while (js_file >> tmp_string && result_of_scanning == not_suspicious_file){
        for (int i=0; i<signatures.size(); i++) {
            result_of_scanning = (tmp_string == signatures[i]);
        }
    }

    js_file.close();

    return result_of_scanning;
}

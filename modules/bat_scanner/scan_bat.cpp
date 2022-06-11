#include "scan_bat.h"

int scan_bat(string filepath){
    vector<string> signatures = get_signatures("../modules/bat_scanner/signatures");

    int result_of_scanning = not_suspicious_file;

    // try to open file
    ifstream bat_file(filepath);

    // if smth wrong -> return error code
    if (bat_file.fail())
        return error_code_;

    string tmp_string;

    // read file line by line while not found suspicious string, use getline() to read all lines, including spaces
    while (getline(bat_file, tmp_string) && result_of_scanning == not_suspicious_file){
        for (int i=0; i<signatures.size(); i++)
            result_of_scanning = (tmp_string == signatures[i]);
    }

    bat_file.close();

    return result_of_scanning;
}
#include "scan_exe.h"

int scan_exe(string filepath){
    vector<string> signatures = get_signatures("../modules/exe_scanner/signatures");

    int result_of_scanning = not_suspicious_file;

    // try to open file
    ifstream exe_file(filepath);

    // if smth wrong -> return error code
    if (exe_file.fail())
        return error_code_;

    // get size of file in bytes
    exe_file.seekg(0, ios::end);
    size_t size_of_file = exe_file.tellg();

    // allocate memory to store file in
    char *buf = new char[size_of_file];

    // reading file into buffer
    exe_file.seekg(0, ios::beg);
    exe_file.read(buf, size_of_file);
    exe_file.close();

    // move buf to string
    string str_file;
    str_file.assign (buf, size_of_file);

    delete [] buf;

    // searching for 1 of suspicious strings
    for (int i=0; i<signatures.size(); i++){
        if ((int)str_file.find(signatures[i]) >=0){
            result_of_scanning = suspicious_file;
            break;
        }
    }


    return result_of_scanning;
}
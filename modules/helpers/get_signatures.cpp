#include "get_signatures.h"

vector<string> get_signatures(string path_to_signatures_file){
    // prepare vector with signatures
    vector<string> signatures;

    // open file with signatures
    ifstream signature_file(path_to_signatures_file);

    // get signatures from file and push it in the vector
    if (signature_file.is_open()){
        string tmp_signature;
        while (getline(signature_file, tmp_signature)){
            signatures.push_back(tmp_signature);
        }
    }

    signature_file.close();
    return signatures;
}
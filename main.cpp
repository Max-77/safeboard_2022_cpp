#include <iostream>
#include <cstring>
#include <filesystem>
#include "scan_js.h"
#include "scan_bat.h"
#include "scan_exe.h"
#include "omp.h"
#include <ctime>

#define NUM_THREADS 4

bool input_dispatcher(int argc, char** argv){
    if (argc!=2){
        std::cout << "Wrong usage! Use help!" << std::endl;
        return false;
    }
    else if (std::strcmp(argv[1], "help") == 0 ){
        std::cout << "Usage: >scan_util {path_to_directory}" << std::endl;
        return false;
    }
    return true;
}

void print_results(bool code_result, int count_of_files, int count_of_js, int count_of_bat,
                   int count_of_exe, int count_of_errors, time_t time_of_working){
    if (code_result){
        std::cout << "====== Scan result ======" << std::endl;
        std::cout << "Processed files: " << count_of_files << std::endl;
        std::cout << "JS detects: " << count_of_js << std::endl;
        std::cout << "BAT detects: " << count_of_bat << std::endl;
        std::cout << "EXE detects: " << count_of_exe << std::endl;
        std::cout << "Errors: " << count_of_errors << std::endl;
        std::cout << "Time of working is: " << time_of_working/3600 << "h:"
        << time_of_working/60 << "m:" << time_of_working << "s"<< std::endl;
    }
    else {
        std::cout << "Not a directory" << std::endl;
    }
}

int main(int argc, char** argv) {
    omp_set_num_threads(NUM_THREADS);

    time_t start_time, end_time;
    time(&start_time);

    if (!input_dispatcher(argc, argv)){
        return 0;
    }

    std::string path_to_dir = argv[1];

    int count_of_files = 0, count_of_suspicious_js = 0,
    count_of_suspicious_bat=0, count_of_suspicious_exe = 0,
    count_of_errors=0;

    bool is_directory_exist = std::filesystem::is_directory(path_to_dir);

    if (is_directory_exist) {
#pragma omp parallel for
        {
            for (const auto &file: std::filesystem::directory_iterator(path_to_dir)) {
                count_of_files++;

                std::string filepath = file.path().string();
                int index_of_last_slash = filepath.find_last_of("\\");
                // get only filename and its extension
                std::string filename = filepath.erase(0, index_of_last_slash + 1);

                // get las 4 chars of filename+extension to avoid situations like: file.js.exe
                std::string shorted_filename = filename.erase(0, filename.size() - 4);

                // rebuild filepath to give it as arguments to functions
                filepath = path_to_dir + "\\" + filepath;

                if ((int) shorted_filename.find("js") > 0) {
                    // launch scan_js to all js files
                    switch (scan_js(filepath)) {
                        case suspicious_file:
                            count_of_suspicious_js++;
                            break;
                        case error_code:
                            count_of_errors++;
                            break;
                    }
                    continue;
                }

                if ((int) shorted_filename.find("bat") > 0 || (int) shorted_filename.find("cmd") > 0) {
                    // launch scan_bat to all bat and cmd files
                    switch (scan_bat(filepath)) {
                        case suspicious_file:
                            count_of_suspicious_bat++;
                            break;
                        case error_code:
                            count_of_errors++;
                            break;
                    }
                    continue;
                }

                if ((int) shorted_filename.find("exe") > 0 || (int) shorted_filename.find("dll") > 0) {
                    // launch scan_exe to all exe and dll files
                    switch (scan_exe(filepath)) {
                        case suspicious_file:
                            count_of_suspicious_exe++;
                            break;
                        case error_code:
                            count_of_errors++;
                            break;
                    }
                    continue;
                }
            }
        }
    }

    time(&end_time);
    time_t time_of_working = end_time - start_time;

    print_results(is_directory_exist, count_of_files, count_of_suspicious_js,
                  count_of_suspicious_bat, count_of_suspicious_exe, count_of_errors, time_of_working);


    return 0;
}

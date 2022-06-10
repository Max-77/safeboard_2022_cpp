# Safeboard spring 2022, C++ development

- #### Requirements: `C++ v.17` or above to directory_iterator support
- #### Compile with flag `-fopenmp` to openMP support
- #### Usage: `>scan_util {path_to_directory}`

### Description:

- main.cpp contains:
  - input_dispatcher to check the input, and help message
  - print_results to print information about count of files, suspicious files and time of working
  - main function that sets omp_num_threads, checks is directory exist, explores filenames in parallel mode and
calls functions if file with necessary filename extension was found
- return_codes.h contains:
  - enum with 3 types of returning codes of functions that explore files:
    - not_suspicious_file if strings wasn't found in file
    - suspicious_file if strings was found in file
    - error_code if something during opening file went wrong 
- scan_js.h contains:
  - scan_js function that reads js file line by line trying to find necessary suspicious string
- scan_bat.h contains:
  - scan_bat function that reads bat and cmd file line by line trying to find necessary suspicious string
- scan_exe.h contains:
  - scan_exe function that reads exe and dll file trying to find necessary suspicious string
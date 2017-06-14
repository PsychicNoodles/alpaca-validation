#include "elf++.hh"
#include "interpose.hh" //interposing exit functions

#include <fcntl.h>
#include <link.h>
#include <unistd.h>

#include <string>

using namespace std;

enum ReturnMode{
        INT,
        FLOAT,
        LARGE
};

/**
 * Locates the address of the target function
 * file_path: the path to the binary file
 * func_name: the name of the target function
 */
uint64_t find_address(const char* file_path, string func_name);

ReturnMode parse_argv(int argc, char** argv);

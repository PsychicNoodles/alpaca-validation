#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#ifndef ALPACA_SHARED
#define ALPACA_SHARED

#include "elf++.hh"
#include "interpose.hh" //interposing exit functions

#include <fcntl.h>
#include <link.h>
#include <unistd.h>

#include <sys/types.h>
#include <dirent.h>

#include <sstream>
#include <string>
#include <map>
#include <fstream>
#include <iostream>

#define ENERGY_ROOT "/sys/class/powercap/intel-rapl/"
#define ENERGY_NAME "name"
#define ENERGY_FILE "energy_uj"
#define ENERGY_LINE_CAPACITY 1024

using namespace std;

extern uint64_t func_address; //the address of the target function

extern fstream return_file;
extern fstream write_file;


/**
 * Locates the address of the target function
 * file_path: the path to the binary file
 * func_name: the name of the target function
 */
uint64_t find_address(const char* file_path, string func_name);

map<string, uint64_t> measure_energy();

#endif

#include "elf++.hh"
#include "interpose.hh"
#include "x86jump.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <link.h>
#include <unistd.h>

#include <fstream>
#include <string>
#include <iostream>
#include <queue>
#include <array>

#define PAGE_SIZE 4096

using std::string;
using std::queue;
using std::array;

std::fstream file; //for logging later
uint64_t func_address; //the address of the target function
bool fpmode;
uint64_t offset; //offset of the main exectuable
queue<uint64_t> rets; //return values for the disabler function
queue<double> fprets;

typedef int (*main_fn_t)(int, char**, char**);
main_fn_t og_main;

static int callback(struct dl_phdr_info *info, size_t size, void *data);
void find_address(const char* file_path, string func_name);
void shut_down();

/**
 * Locates the address of the target function
 * file_path: the path to the binary file
 * func_name: the name of the target function
 */
void find_address(const char* file_path, string func_name) {
        uint64_t addr;

        int read_fd = open(file_path, O_RDONLY);
        if (read_fd < 0) {
                fprintf(stderr, "%s: %s\n", file_path, strerror(errno));
                exit(2);
        }

        elf::elf f(elf::create_mmap_loader(read_fd));
        for (auto &sec : f.sections()) {
                if (sec.get_hdr().type != elf::sht::symtab) continue;

                for (auto sym : sec.as_symtab()) {
                        auto &d = sym.get_data();
                        if (d.type() != elf::stt::func || sym.get_name() != func_name) continue;

                        addr = offset + d.value; 
                }
        }

        func_address = addr;
        //potential problem with multiple entries in the table for the same function? 
}

/**
 * Accesses the entry for the main executable on first execution of callback
 * Passed as a parameter to dl_iterate_phdr()
 * dl_phdr_info: a pointer to a structure containing info about the shared object 
 * size: size of the shared object 
 * data: a copy of value passed by dl_iterate_phdr();
 * @returns a non-zero value until there are no shared objects to be processed. 
 */
static int callback(struct dl_phdr_info *info, size_t size, void *data) {
        // or info->dlpi_name == "\0" if first run doesn't work ?
        static int run = 0;
        if (run) return 0;

        offset = info->dlpi_addr; 
        run = 1;
        return 0; 
}

uint64_t int_disabled_func() {
        uint64_t val = rets.front();
        rets.pop();
        return val;
}

double double_disabled_func() {
        double val = fprets.front();
        fprets.pop();
        return val;
}

/**
 * Fake main that intercepts the main of a program running the analyzer tool
 * takes in the arguments passed on running 
 */
static int wrapped_main(int argc, char** argv, char** env) {
        fprintf(stderr, "Entered main wrapper\n");

        fpmode = string(argv[argc-2]).compare("fp") == 0;
        
        //storing the func_name searched for as the last argument
        string func_name = argv[argc-1];  
        argv[argc-1] = NULL;
        argc--;

        dl_iterate_phdr(callback, NULL);
        find_address("/proc/self/exe", func_name);
        
       
        string line; 
        file.open("read-logger", std::fstream::in | std::fstream::binary);

        while(!file.eof()) {
                if(fpmode) {
                        uint32_t buffer[4];
                        for(int i = 0; i < 4; i++) {
                                file.read((char*) &buffer[i], sizeof(uint32_t));
                        }

                        fprets.push(*((double*)buffer));
                } else {
                        uint32_t buffer[2] = {0};
                        file.read((char*)buffer, sizeof(buffer));

                        rets.push((uint64_t)ntohl(buffer[0]) << 32 | (uint64_t)ntohl(buffer[1]));
                }

        }

        uint64_t page_start = func_address & ~(PAGE_SIZE-1) ;

        //making the page writable, readable and executable
        if (mprotect((void*) page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
                fprintf(stderr, "%s\n", strerror(errno));
                exit(2); 
        }
                
        if(fpmode) new((void*)func_address) X86Jump((void*)double_disabled_func);
        else new((void*)func_address) X86Jump((void*)int_disabled_func);

        //energy measurements and running the input program 
        std::ifstream energy_file("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj", std::ios_base::in);
        unsigned long long energy_before, energy_after; 
        energy_file >> energy_before;

        og_main(argc, argv, env);

        energy_file.seekg(0); 
        energy_file >> energy_after;
        fprintf(stderr, "Energy with disabled function: %llu\n", (energy_after-energy_before));
        
        energy_file.close();
        file.close();
    
        return 0; 
}

/**
 * Intercepts __libc_start_main call to override main of the program calling the analyzer tool
 * Code retrieved from https://github.com/plasma-umass/coz/blob/master/libcoz/libcoz.cpp
 *                 and https://github.com/ccurtsinger/interpose
 */
extern "C" int __libc_start_main(main_fn_t main_fn, int argc, char** argv, void (*init)(),
                void (*fini)(), void (*rtld_fini)(), void* stack_end) {

        //Find original __libc_start_main
        auto og_libc_start_main = (decltype(__libc_start_main)*)dlsym(RTLD_NEXT, "__libc_start_main");

        //Save original main function
        og_main = main_fn;

        //Running original __libc_start_main with wrapped main
        return og_libc_start_main(wrapped_main, argc, argv, init, fini, rtld_fini, stack_end); 
}

INTERPOSE (exit)(int rc) {
        shut_down();
        real::exit(rc);
}

INTERPOSE (_exit)(int rc) {
        shut_down();
        real::_exit(rc); 
}

INTERPOSE (_Exit)(int rc) {
        shut_down();
        real::_Exit(rc); 
}

void shut_down() {
        //close(log_fd);
}
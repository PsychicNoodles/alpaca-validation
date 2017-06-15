#include "alpaca_shared.hh"

#include "elf++.hh"
#include "x86jump.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <link.h>
#include <unistd.h>

#include <fstream>
#include <string>
#include <iostream>
#include <queue>
#include <array>

#define PAGE_SIZE 4096

using namespace std;

fstream return_file; //for logging later
fstream write_file; //for logging later
uint64_t func_address; //the address of the target function
ReturnMode return_mode;
queue<uint64_t> rets; //return values for the disabler function
queue<double> fprets;
queue<uint64_t> write_count; 
queue<uint64_t> writes; //returning from write-logger
queue<void*> ptrrets;

typedef int (*main_fn_t)(int, char**, char**);
main_fn_t og_main;

void mimic_writes(uint64_t write_count);

uint64_t int_disabled_func() {
        uint64_t wc = write_count.front();
        write_count.pop();
        if (wc != 0) mimic_writes(wc);
        
        uint64_t val =  rets.front();
        rets.pop();
        return val;
}

double double_disabled_func() {
        uint64_t wc =write_count.front();
        write_count.pop();
        if (wc != 0) mimic_writes(wc);
        
        double val = fprets.front();
        fprets.pop();
        return val;
}

void* large_disabled_func() {
        uint64_t wc =write_count.front();
        write_count.pop();
        if (wc != 0) mimic_writes(wc);
        
        void* ptr = ptrrets.front();
        ptrrets.pop();
        return ptr;
}

void mimic_writes(uint64_t write_count) {
        fprintf(stderr, "mimicing writes with count %lu\n", write_count);
        for(int i = 0; i < write_count; i++){
                uint64_t* memory_dest = (uint64_t*) writes.front();
                writes.pop();
                uint64_t val = writes.front();
                writes.pop();

                *memory_dest = val;
                fprintf(stderr, "wrote %lu into %p\n", val, (void*)memory_dest);
        }
}

/**
 * Fake main that intercepts the main of a program running the analyzer tool
 * takes in the arguments passed on running 
 */
static int wrapped_main(int argc, char** argv, char** env) {
        fprintf(stderr, "Entered main wrapper\n");

        return_mode = parse_argv(argc, argv);
        
        //storing the func_name searched for as the last argument
        string func_name = argv[argc-1];  
        argv[argc-1] = NULL;
        argv[argc-2] = NULL;
        argc -= 2;

        func_address = find_address("/proc/self/exe", func_name);
        
       
        string line; 
        return_file.open("return-logger", fstream::in | fstream::binary);
        write_file.open("write-logger", fstream::in | fstream::binary);

        while (!write_file.eof()) {
                uint64_t buffer; 
                write_file.read((char*) &buffer, sizeof(uint64_t));
                writes.push(buffer); 
        }
        
        while(!return_file.eof()) {
                uint64_t wr_buffer;
                return_file.read((char*) &wr_buffer, sizeof(uint64_t));
                write_count.push(wr_buffer);
                
                if(return_mode == FLOAT) {
                        uint32_t buffer[4];
                        for(int i = 0; i < 4; i++) {
                                return_file.read((char*) &buffer[i], sizeof(uint32_t));
                        }

                        fprets.push(*((double*)buffer));
                } else if(return_mode == LARGE) {
                        uint32_t buffer[2] = {0};
                        return_file.read((char*)buffer, sizeof(buffer));

                        uint64_t p = ((uint64_t)ntohl(buffer[0]) << 32 | (uint64_t)ntohl(buffer[1]));
                        ptrrets.push((void*)p);
                } else if(return_mode == INT) {
                        uint32_t buffer[2] = {0};
                        return_file.read((char*)buffer, sizeof(buffer));

                        rets.push((uint64_t)ntohl(buffer[0]) << 32 | (uint64_t)ntohl(buffer[1]));
                } else {
                        fprintf(stderr, "Invalid return type mode\n");
                        exit(3);
                }
        }

        uint64_t page_start = func_address & ~(PAGE_SIZE-1) ;

        //making the page writable, readable and executable
        if (mprotect((void*) page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
                fprintf(stderr, "%s\n", strerror(errno));
                exit(2); 
        }
                
        if(return_mode == FLOAT) new((void*)func_address) X86Jump((void*)double_disabled_func);
        else if(return_mode == LARGE) new((void*)func_address) X86Jump((void*) large_disabled_func);
        else if(return_mode == INT) new((void*)func_address) X86Jump((void*)int_disabled_func);

        map<string, uint64_t> start_readings = measure_energy();
        
        og_main(argc, argv, env);

        map<string, uint64_t> end_readings = measure_energy();

        printf("Energy consumption (%lu):\n", end_readings.size());
        for(auto &ent : end_readings) {
                printf("%s: %lu\n", ent.first.c_str(), ent.second - start_readings.at(ent.first));
        }
        
        return_file.close();
    
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

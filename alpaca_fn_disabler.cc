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
#include <queue>

#define PAGE_SIZE 4096

using std::string;

std::fstream file; //for logging later
uint64_t func_address; //the address of the target function
uint64_t offset; //offset of the main exectuable
std::queue<uint64_t> rets; //return values for the disabler function

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

                /*
                fprintf(stderr, "Section '%s':\n", sec.get_name().c_str());
                fprintf(stderr, "%-16s %-5s %-7s %-5s %s %s\n",
                                "Address", "Size", "Binding", "Index", "Name", "Type");
                */

                for (auto sym : sec.as_symtab()) {
                        auto &d = sym.get_data();
                        if (d.type() != elf::stt::func || sym.get_name() != func_name) continue;

                        /*
                        //probably will end up writing to log_fd
                        fprintf(stderr, "0x%-16lx %-5lx %-7s %5s %s %s\n",
                                        offset + d.value, d.size,
                                        to_string(d.binding()).c_str(),
                                        to_string(d.shnxd).c_str(),
                                        sym.get_name().c_str(),
                                        to_string(d.type()).c_str());
                        */

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

uint64_t disabled_func() {
        uint64_t val = rets.front();
        rets.pop();
        return val;
}

/**
 * Fake main that intercepts the main of a program running the analyzer tool
 * takes in the arguments passed on running 
 */
static int wrapped_main(int argc, char** argv, char** env) {
        fprintf(stderr, "Entered main wrapper\n");
        
        //storing the func_name searched for as the last argument
        string func_name = argv[argc-1];  
        argv[argc-1] = NULL;
        argc--;

        dl_iterate_phdr(callback, NULL);
        find_address("/proc/self/exe", func_name);
        
       
        string line; 
        file.open("read-logger", std::fstream::in | std::fstream::binary);

        while(!file.eof()) {
                uint32_t buffer[2] = {0};
                file.read((char*)buffer, sizeof(buffer));
                //fprintf(stderr, "read from file: %d %d\n", buffer[0], buffer[1]);

                rets.push((uint64_t)ntohl(buffer[0]) << 32 | (uint64_t)ntohl(buffer[1]));

//                        fprintf(stderr, "return in ret %d\n", (int) rets.front()); 

        }

//                fprintf(stderr, "%d\n", ((int(*)()) func_address)());

        uint64_t page_start = func_address & ~(PAGE_SIZE-1) ;

        //making the page writable, readable and executable
        if (mprotect((void*) page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
                fprintf(stderr, "%s\n", strerror(errno));
                exit(2); 
        }
                
        //              fprintf(stderr, "inserting jump from %p to %p\n", (void*) func_address, (void*) disabled_func);
        new((void*)func_address) X86Jump((void*)disabled_func);
        //fprintf(stderr, "jump inserted\n");

//        fprintf(stderr, "starting main\n");
        og_main(argc, argv, env);
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

#define _GNU_SOURCE
#include <dlfcn.h>

//citations: modified example code from
//https://github.com/aclements/libelfin/blob/master/examples/dump-syms.cc
#include "elf++.hh"
#include "interpose.hh"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <link.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096
int log_fd;
std::uint64_t offset;

void shut_down(); 

std::uint64_t find_address(const char* file_path, std::string func_name) {

        std::uint64_t addr;

        int read_fd = open(file_path, O_RDONLY);
        if (read_fd < 0) {
                fprintf(stderr, "%s: %s\n", file_path, strerror(errno));
                exit(2);
        }
        
        elf::elf f(elf::create_mmap_loader(read_fd));
        for (auto &sec : f.sections()) {
                if (sec.get_hdr().type != elf::sht::symtab) continue;

                printf("Section '%s':\n", sec.get_name().c_str());
                printf("%-16s %-5s %-7s %-5s %s %s\n",
                       "Address", "Size", "Binding", "Index", "Name", "Type");
                
                for (auto sym : sec.as_symtab()) {
                        auto &d = sym.get_data();
                        if (d.type() != elf::stt::func || sym.get_name() != func_name) continue;

                        //probably will end up writing to log_fd
                        printf("0x%-16lx %-5lx %-7s %5s %s %s\n",
                               offset + d.value, d.size,
                               to_string(d.binding()).c_str(),
                               to_string(d.shnxd).c_str(),
                               sym.get_name().c_str(),
                               to_string(d.type()).c_str());

                        addr = offset + d.value; 
               }
        }

        return addr; 
}

void single_step(std::uint64_t func_address, std::size_t page_size) {

        std::uint64_t page_start = func_address & ~(page_size-1) ;

        //making the page writable, readable and executable
        if (-1 == mprotect((void*) page_start, page_size, PROT_READ| PROT_WRITE| PROT_EXEC)) {
            fprintf(stderr, "%s\n", strerror(errno));
            exit(2); 
        }

        std::uint64_t remembered_byte = func_address & ~0xff; 
        //setting the last byte to 0xCC causes a SIGTRAP signal for single-stepping
        *(int*)func_address = (func_address & ~0xff) | 0xCC;
}
//returns the entry for the main executable on first execution of callback
// or info->dlpi_name == "\0" ?
static int callback(struct dl_phdr_info *info, size_t size, void *data) {
        
        static int run = 0;

        if (run) return 0;
        
        offset = info->dlpi_addr; 
        run = 1;
        return 0; 
}

typedef int (*main_fn_t)(int, char**, char**);
main_fn_t og_main;

void handler(int signal, siginfo_t* info, void* cont) {
        
        if (signal != SIGTRAP) exit(2);
        printf("cought SIGTRAP\n");
        
        // process assembly instruction info w m_context
        ucontext_t* context = reinterpret_cast<ucontext_t*>(context);
        printf("hi\n");
        //address of the next assembly instruction to be executed
        printf("Stack starts at: 0x%llx\n", context->uc_mcontext.gregs[REG_RBP]);  
}

void seg_handler(int signal) {
        if (signal != SIGSEGV) exit(2);

        char** buffer = (char**)malloc(sizeof(char)*256*200);

        



}




static int wrapped_main(int argc, char** argv, char** env) {

        printf("Entered main wrapper\n");

        //set up for the signal handler
        struct sigaction sig_action;
        memset(&sig_action, 0, sizeof(sig_action));
        sig_action.sa_sigaction = handler;
        sigemptyset(&sig_action.sa_mask);
        sig_action.sa_flags = SA_SIGINFO;

        sigaction(SIGTRAP, &sig_action, 0);
        signal(SIGSEGV, seg_handler);

        //storing the func_name searched for as the last argument
        std::string func_name = argv[argc-1];  
        argv[argc-1] = NULL;

        //getting the address of the main executable for the offset 
        dl_iterate_phdr(callback, NULL);
        
        std::uint64_t address = find_address("/proc/self/exe", func_name);
        
        single_step(address, PAGE_SIZE);
        
        og_main(argc, argv, env); 
}


//Code retrieved from https://github.com/plasma-umass/coz/blob/master/libcoz/libcoz.cpp
//                and https://github.com/ccurtsinger/interpose
extern "C" int __libc_start_main(main_fn_t main_fn, int argc, char** argv, void (*init)(),
                               void (*fini)(), void (*rtld_fini)(), void* stack_end) {

        //Find original __libc_start_main
        auto og_libc_start_main = (decltype(__libc_start_main)*)dlsym(RTLD_NEXT, "__libc_start_main");
        
        //Save original main function
        og_main = main_fn;

        //Running original __libc_start_main with wrapped main
        return og_libc_start_main(wrapped_main, argc, argv, init, fini, rtld_fini, stack_end); 
}

//Code retrieved from Mattori & 213 partners
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
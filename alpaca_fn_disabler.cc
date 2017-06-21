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


typedef struct {
        uint8_t flag;
        uint64_t rax;
        uint64_t rdx;
        float xmm0[4];
        float xmm1[4]; 
} ret_t; 


queue<ret_t> returns;

queue<uint64_t> write_count_queue; 
queue<uint64_t> writes; //returning from write-logger

void mimic_writes_disabler(uint64_t write_count);

void disabled_fn() {
        fprintf(stderr, "disabled_fn\n");

        uint64_t wc = write_count_queue.front();
        write_count_queue.pop();

        if (wc != 0) mimic_writes_disabler(wc);

        ret_t curr_return = returns.front();
        returns.pop();

        fprintf(stderr, "flag: %d\n", curr_return.flag);

        if(curr_return.flag & 0b11110000) {
                fprintf(stderr, "only rax and rdx supported (%d)\n", curr_return.flag);
                exit(5);
        }

        if(curr_return.flag & 0b00001000) fprintf(stderr, "xmm1: %lf %lf %lf %lf\n", curr_return.xmm1[0], curr_return.xmm1[1],  curr_return.xmm1[2],  curr_return.xmm1[3]);
        if(curr_return.flag & 0b00000100) fprintf(stderr, "xmm0: %lf %lf %lf %lf\n", curr_return.xmm0[0], curr_return.xmm0[1],  curr_return.xmm0[2],  curr_return.xmm0[3]);

                
        if(curr_return.flag & 0b00000010) fprintf(stderr, "rdx: %lu\n", curr_return.rdx);
        if(curr_return.flag & 0b00000001) fprintf(stderr, "rax: %lu\n", curr_return.rax);
 
        if(curr_return.flag & 0b00001000) asm("movdqu (%0), %%xmm1" : : "r"(curr_return.xmm1) : );
        if(curr_return.flag & 0b00000100) asm("movdqu (%0), %%xmm0" : : "r"(curr_return.xmm0) : );
        
        if(curr_return.flag & 0b00000010) asm("" : : "d"(curr_return.rdx) : );
        //other registers and if statements (comparison) use rax to store their values so it should come last 
        if(curr_return.flag & 0b00000001) asm("" : : "a"(curr_return.rax) : );
}


void mimic_writes_disabler(uint64_t write_count) {
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

//first log memory address
//second log value at the mem address (both uint64_t)
void read_writes() {
        uint64_t buf;
        while (write_file.read((char*) &buf, sizeof(uint64_t))) {
                writes.push(buf);
                fprintf(stderr, "logged writes in disabler: %p\n", (void*)buf);
        }
}

//first log number of writes
//second log return struct

void read_returns() {
        uint64_t buf;
        while(return_file.read((char*) &buf, sizeof(uint64_t))) {
                cerr << "return_file tellg: " << return_file.tellg() << "\n";
                fprintf(stderr, "wc: %lu\n", buf);
                write_count_queue.push(buf);

                ret_t return_struct; 
                return_file.read((char*) &return_struct.flag, 1);
                fprintf(stderr, "flag is: %d\n", return_struct.flag);

                if(return_struct.flag & 0b00000001) return_file.read((char*) &return_struct.rax, 8);
                if(return_struct.flag & 0b00000010) return_file.read((char*) &return_struct.rdx, 8);

                if(return_struct.flag & 0b00000100) {
                        for (int i = 0; i < 4; i ++) return_file.read((char*) &return_struct.xmm0[i], sizeof(float));
                        fprintf(stderr, "xmm0: %.1f %.1f %.1f %.1f\n", return_struct.xmm0[0], return_struct.xmm0[1], return_struct.xmm0[2], return_struct.xmm0[3]);
                }

                if(return_struct.flag & 0b00001000) {
                        for (int i = 0; i < 4; i ++) return_file.read((char*) &return_struct.xmm1[i], sizeof(float));

                        fprintf(stderr, "xmm1: %.1f %.1f %.1f %.1f\n", return_struct.xmm1[0], return_struct.xmm1[1], return_struct.xmm1[2], return_struct.xmm1[3]);
                }

                returns.push(return_struct);
        }
        
        uint64_t page_start = func_address & ~(PAGE_SIZE-1) ;

        //making the page writable, readable and executable
        if (mprotect((void*) page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
                fprintf(stderr, "%s\n", strerror(errno));
                exit(2); 
        }

        new((void*)func_address)X86Jump((void*)disabled_fn);

        //switch back to old permissions! 
}

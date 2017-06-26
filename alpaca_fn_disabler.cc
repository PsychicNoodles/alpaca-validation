#include "alpaca_shared.hh"

#include "elf++.hh"
#include "x86jump.h"

#include <arpa/inet.h>
#include <bitset>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <link.h>
#include <unistd.h>

#include <fstream>
#include <iostream>

#define PAGE_SIZE 4096

using namespace std;

typedef struct {
  uint8_t flag;
  uint64_t rax;
  uint64_t rdx;
  float xmm0[4];
  float xmm1[4]; 
} ret_t; 


ret_t returns[MAX_RETURNS];
size_t returns_index = 0;
size_t returns_filled = 0; 

uint64_t write_syscall_counts[MAX_RETURNS];
size_t write_syscall_counts_index = 0;
size_t write_syscall_counts_filled = 0;

bool flags[MAX_SYSCALLS + MAX_WRITES];
size_t flags_index = 0;
size_t flags_filled = 0;

uint64_t syses[MAX_SYSCALLS];
size_t syses_index = 0;
size_t syses_filled = 0;

uint64_t writes[MAX_WRITES]; //returning from write-logger
size_t writes_index = 0;
size_t writes_filled = 0;

void mimic_write();
bool mimic_syscall();

void disabled_fn() {
  fprintf(stderr, "disabled_fn\n");

  if (write_syscall_counts_index > write_syscall_counts_filled) {
          fprintf(stderr, "write_syscall_counts_index out of bounds!\n");
          exit(2);
  }

  uint64_t count = write_syscall_counts[write_syscall_counts_index++];
  
  fprintf(stderr, "write/syscall count %lu\n", count);
  for(int i = 0; i < count; i++) {

    if (flags_index > flags_filled) {
            fprintf(stderr, "flags_index out of bounds!\n");
            exit(2);
    }

    bool flag = flags[flags_index++];
    fprintf(stderr, "flag pop: %d\n", flag ? 1 : 0);
    if(flag) {
      fprintf(stderr, "mimicing write\n");
      mimic_write();
    } else {
      if (!mimic_syscall()) {
        fprintf(stderr, "syscall mimicing failed!\n");
        exit(2);
      }
    }
  }

  if (returns_index > returns_filled) {
          fprintf(stderr, "returns_index is out of bounds!\n");
          exit(2);
  }

  ret_t curr_return = returns[returns_index++];

  fprintf(stderr, "flag: %d\n", curr_return.flag);

  if(curr_return.flag & 0b00001000) fprintf(stderr, "xmm1: %.1f %.1f %.1f %.1f\n", curr_return.xmm1[0], curr_return.xmm1[1], curr_return.xmm1[2], curr_return.xmm1[3]);
  if(curr_return.flag & 0b00000100) fprintf(stderr, "xmm0: %.1f %.1f %.1f %.1f\n", curr_return.xmm0[0], curr_return.xmm0[1], curr_return.xmm0[2], curr_return.xmm0[3]);
        
  if(curr_return.flag & 0b00000010) fprintf(stderr, "rdx: %lu\n", curr_return.rdx);
  if(curr_return.flag & 0b00000001) fprintf(stderr, "rax: %lu\n", curr_return.rax);

  if(curr_return.flag & 0b00001000) {
          asm("movdqu (%0), %%xmm1" : : "r"(curr_return.xmm1) : );
//          fprintf(stderr, "moving into xmm1\n");
  }
          
  if(curr_return.flag & 0b00000100) {
          asm("movdqu (%0), %%xmm0" : : "r"(curr_return.xmm0) : );
//          fprintf(stderr, "moving into xmm0\n");
  }
  
  if(curr_return.flag & 0b00000010) {
          asm("" : : "d"(curr_return.rdx) : );
//           fprintf(stderr, "moving into rdx\n");
  }
  //other registers and if statements (comparison) use rax to store their values so it should come last
  
  if(curr_return.flag & 0b00000001) {
          asm("" : : "a"(curr_return.rax) : );
//        fprintf(stderr, "moving into rax\n");
  }

  //fprintf(stderr, "disble function successful!\n");
}

//returns true upon correctly mimicing a syscall
bool mimic_syscall() {

        for (int i = 0; i < 10; i++) {
                fprintf(stderr, "some values after syscall called: %lu, at index %lu\n", syses[syses_index + i], syses_index + i);

        }

        if (syses_index > syses_filled) {
                fprintf(stderr, "syses_index is out of bounds (%zu at initial)!\n", syses_index);
                exit(2);
        }
        uint64_t sys_num = syses[syses_index++];

        syscall_t syscall_struct = syscalls[sys_num];
        int args_no = syscall_struct.args;
        fprintf(stderr, "mimicing syscall %lu name %s num args %d\n", sys_num, syscall_struct.name.c_str(), args_no);

        if (syses_index + args_no + 1 > syses_filled) { //+1 for the return 
                fprintf(stderr, "syses_index is out of bounds (%zu at params)!\n", syses_index);
                exit(2);
        }

        
        uint64_t param_regs[6];//temp_rdi, temp_rsi, temp_rdx, temp_r10, temp_r8, temp_r9; 

        for (int i = 0; i < args_no; i++) {
                fprintf(stderr, "syscall param %d is %lu\n", i, syses[syses_index]);
                param_regs[i] = syses[syses_index++];
        }
        
 
        if (args_no > 0) asm("mov %0, %%rdi" : : "r"(param_regs[0]) : );
        if (args_no > 3) asm("mov %0, %%r10" : : "r"(param_regs[3]) : );
        if (args_no > 4) asm("mov %0, %%r8" : : "r"(param_regs[4]) : );
        if (args_no > 5) asm("mov %0, %%r9" : : "r"(param_regs[5]) : );
        if (args_no > 1) asm("mov %0, %%rsi" : : "r"(param_regs[1]) : );
        if (args_no > 2) asm("mov %0, %%rdx" : : "r"(param_regs[2]) : );

        //calling
        asm("mov %0, %%rax; syscall": : "r" (sys_num):);
 
        uint64_t curr_ret;
        asm("mov %%rax, %0": "=r" (curr_ret): :);

        // uint64_t original_ret = syses[syses_index++];
        fprintf(stderr, "expected %lx ret, got %lx\n", syses[syses_index++], curr_ret);
        return syses[syses_index-1] == curr_ret; 
}

void mimic_write() {
        fprintf(stderr, "time to mimic writes\n");
        if (writes_index + 1 > writes_filled) { // + 1 for value
                fprintf(stderr, "writes_index is out of bounds!\n");
                exit(2);
        }

        fprintf(stderr, "getting mem dest\n");
        uint64_t* memory_dest = (uint64_t*) writes[writes_index++];
        fprintf(stderr, "getting val\n");
        uint64_t val = writes[writes_index++];
        fprintf(stderr, "got %p mem and %lu val\n", memory_dest, val);

        *memory_dest = val;
        fprintf(stderr, "wrote %lu into %p\n", val, (void*)memory_dest);
}

void read_syscalls(){
        fprintf(stderr, "reading syscalls\n");
  
        uint64_t buffer; 
        while(sys_file.read((char*) &buffer, sizeof(uint64_t))){

                if (syses_filled >= MAX_SYSCALLS) {
                        fprintf(stderr, "syses_filled is out of bounds!\n");
                        exit(2);
                }

                fprintf(stderr, "read syscall num %lu\n", buffer);
                syses[syses_filled++] = buffer;
                uint64_t num_params = syscalls[buffer].args;
                
                if (syses_filled + num_params + 1 >= MAX_SYSCALLS) { // +1 for return
                        fprintf(stderr, "syses_filled is out of bounds!\n");
                        exit(2);
                }

                fprintf(stderr, "reading %lu syscall params\n", num_params);
                for (int i = 0; i < num_params; i++) {
                        sys_file.read((char*) &buffer, sizeof(uint64_t));
                        fprintf(stderr, "read param %lu\n", buffer);
                        syses[syses_filled++] = buffer;
                }
                fprintf(stderr, "reading in syscall ret\n");
                sys_file.read((char*) &buffer, sizeof(uint64_t));
                
                fprintf(stderr, "reading return in read syscalls %lu\n", buffer);
                syses[syses_filled++] = buffer;
        }
}


//first log memory address
//second log value at the mem address (both uint64_t)
void read_writes() {
        uint64_t buffer;
        while (write_file.read((char*) &buffer, sizeof(uint64_t))) {
                if (writes_filled >= MAX_WRITES) {
                        fprintf(stderr, "writes_filled is out of bounds!\n");
                        exit(2);
                }
          
                writes[writes_filled++] = buffer;
                //fprintf(stderr, "logged writes in disabler: %p (uint64_t %lu)\n", (void*)buffer, buffer);
        }
}

//first log number of writes
//second log return struct

void read_returns() {

        uint64_t write_sys_count;
        while(return_file.read((char*) &write_sys_count, sizeof(uint64_t))) {
                fprintf(stderr, "write_sys_count %lu\n", write_sys_count);

                if (write_syscall_counts_filled >= MAX_RETURNS) {
                        fprintf(stderr, "write_sys_count_filled is out of bounds!\n");
                        exit(2);
                }
     
                write_syscall_counts[write_syscall_counts_filled++] = write_sys_count; 

                fprintf(stderr, "reading write/syscall flag ");
                for (int i = 0; i < (write_sys_count/8) + 1; i++) {
                        uint8_t buf;
                        return_file.read((char*) &buf, sizeof(uint8_t));

                        bitset<8> byte(buf); 
                        for (int j = 0; j < 8; j++) {

                                if (flags_filled >= (MAX_RETURNS + MAX_SYSCALLS)) {
                                        fprintf(stderr, "flags_filled is out of bounds!\n");
                                        exit(2);
                                }
                                flags[flags_filled++] = byte.test(j);
                                fprintf(stderr, "%d", byte.test(j) ? 1 : 0);
                        }
                        fprintf(stderr, " ");
                }
                fprintf(stderr, "\n");
    

                ret_t return_struct; 
                return_file.read((char*) &return_struct.flag, 1);
                fprintf(stderr, "flag %hhu\n", return_struct.flag);

                if(return_struct.flag & 0b00000001) {
                        return_file.read((char*) &return_struct.rax, 8);
                        fprintf(stderr, "rax %lu\n", return_struct.rax);
                }
                if(return_struct.flag & 0b00000010) {
                        return_file.read((char*) &return_struct.rdx, 8);
                        fprintf(stderr, "rdx %lu\n", return_struct.rdx);
                }

                if(return_struct.flag & 0b00000100) {
                        for (int i = 0; i < 4; i ++) return_file.read((char*) &return_struct.xmm0[i], 4);
                        fprintf(stderr, "logging value: %lf\n", *((double*)return_struct.xmm0));
                }

                if(return_struct.flag & 0b00001000) {
                        for (int i = 0; i < 4; i ++) return_file.read((char*) &return_struct.xmm1[i], 4);
                }

                if (returns_filled >= MAX_RETURNS) {
                        fprintf(stderr, "returns_filled is out of bounds!\n");
                        exit(2);
                }
                
                returns[returns_filled++] = return_struct;
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

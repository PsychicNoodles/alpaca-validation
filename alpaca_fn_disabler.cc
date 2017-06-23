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
queue<uint64_t> write_syscall_counts;
queue<bool> flags;
queue<uint64_t> syses;
queue<uint64_t> writes; //returning from write-logger

void mimic_write();
bool mimic_syscall();

void disabled_fn() {
  fprintf(stderr, "disabled_fn\n");

  uint64_t count = write_syscall_counts.front();
  write_syscall_counts.pop();
  fprintf(stderr, "write/syscall count %lu\n", count);
  for(int i = 0; i < count; i++) {
    fprintf(stderr, "flag pop: %d\n", flags.front() ? 1 : 0);
    if(flags.front()) {
      fprintf(stderr, "mimicing write\n");
      mimic_write();
    } else {
      if (!mimic_syscall()) {
        fprintf(stderr, "syscall mimicing failed!\n");
        exit(2);
      }
    }
    flags.pop();
  }

  ret_t curr_return = returns.front();
  returns.pop();

  fprintf(stderr, "flag: %d\n", curr_return.flag);

  if(curr_return.flag & 0b00001000) fprintf(stderr, "xmm1: %.1f %.1f %.1f %.1f\n", curr_return.xmm1[0], curr_return.xmm1[1], curr_return.xmm1[2], curr_return.xmm1[3]);
  if(curr_return.flag & 0b00000100) fprintf(stderr, "xmm0: %.1f %.1f %.1f %.1f\n", curr_return.xmm0[0], curr_return.xmm0[1], curr_return.xmm0[2], curr_return.xmm0[3]);
        
  if(curr_return.flag & 0b00000010) fprintf(stderr, "rdx: %lu\n", curr_return.rdx);
  if(curr_return.flag & 0b00000001) fprintf(stderr, "rax: %lu\n", curr_return.rax);

  if(curr_return.flag & 0b00001000) asm("movdqu (%0), %%xmm1" : : "r"(curr_return.xmm1) : );
  
  if(curr_return.flag & 0b00000100) asm("movdqu (%0), %%xmm0" : : "r"(curr_return.xmm0) : );
  
  if(curr_return.flag & 0b00000010) asm("" : : "d"(curr_return.rdx) : );
  //other registers and if statements (comparison) use rax to store their values so it should come last
  
  if(curr_return.flag & 0b00000001) asm("" : : "a"(curr_return.rax) : );
}

//returns true upon correctly mimicing a syscall
bool mimic_syscall() {
  uint64_t sys_num = syses.front();
  syses.pop();

  syscall_t syscall_struct = syscalls[sys_num];
  int args_no = syscall_struct.args;
  fprintf(stderr, "mimicing syscall %lu name %s num args %d\n", sys_num, syscall_struct.name.c_str(), args_no);
   
  if (args_no > 0) {
    asm("mov %0, %%rdi" : : "r"(syses.front()) : );
    syses.pop();
  } if (args_no > 1) {
    asm("mov %0, %%rsi" : : "r"(syses.front()) : );
    syses.pop();
  } if (args_no > 2) {
    asm("mov %0, %%rdx" : : "r"(syses.front()) : );
    syses.pop();
  } if (args_no > 3) {
    asm("mov %0, %%r10" : : "r"(syses.front()) : );
    syses.pop();
  } if (args_no > 4) {
    asm("mov %0, %%r8" : : "r"(syses.front()) : );
    syses.pop();
  } if (args_no > 5) {
    asm("mov %0, %%r9" : : "r"(syses.front()) : );
    syses.pop();
  }


  uint64_t original_ret = syses.front();
  syses.pop(); 

  //calling
  asm("mov %0, %%rax; syscall": : "r" (sys_num):);
 
  uint64_t curr_ret;
  asm("mov %%rax, %0": "=r" (curr_ret): :);
  return original_ret == curr_ret; 
 
}

void mimic_write() {
  uint64_t* memory_dest = (uint64_t*) writes.front();
  writes.pop();
  uint64_t val = writes.front();
  writes.pop();

  *memory_dest = val;
  fprintf(stderr, "wrote %lu into %p\n", val, (void*)memory_dest);
}

void read_syscalls(){
  fprintf(stderr, "reading syscalls\n");
  uint64_t buffer; 
  while(sys_file.read((char*) &buffer, sizeof(uint64_t))){
    syses.push(buffer);
    uint64_t num_params = syscalls[buffer].args;
    for (int i = 0; i < num_params; i++) {
      sys_file.read((char*) &buffer, sizeof(uint64_t)); 
      syses.push(buffer);
    }
    fprintf(stderr, "logged syscall in disabler: %p\n", (void*)buffer);
  }
}


//first log memory address
//second log value at the mem address (both uint64_t)
void read_writes() {
  uint64_t buffer;
  while (write_file.read((char*) &buffer, sizeof(uint64_t))) {
    writes.push(buffer);
    fprintf(stderr, "logged writes in disabler: %p (uint64_t %lu) ", (void*)buffer, buffer);
    for(int i = 0; i < 2; i++) fprintf(stderr, "(uint32_t[%d] %u) ", i, ((uint32_t*)&buffer)[i]);
    for(int i = 0; i < 8; i++) fprintf(stderr, "(uint8_t[%d] %u) ", i, ((uint8_t*)&buffer)[i]);
    fprintf(stderr, "\n");
  }
}

//first log number of writes
//second log return struct

void read_returns() {
  uint64_t write_sys_count;
  while(return_file.read((char*) &write_sys_count, sizeof(uint64_t))) {
    fprintf(stderr, "write_sys_count %lu\n", write_sys_count);
    write_syscall_counts.push(write_sys_count); 

    fprintf(stderr, "reading write/syscall flag ");
    for (int i = 0; i < (write_sys_count/8) + 1; i++) {
      uint8_t buf;
      return_file.read((char*) &buf, sizeof(uint8_t));

      bitset<8> byte(buf); 
      for (int j = 0; j < 8; j++) {
        flags.push(byte.test(j));
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

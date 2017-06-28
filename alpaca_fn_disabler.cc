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

// queues
/// return registers
ret_t returns[MAX_RETURNS];
size_t returns_index = 0;
size_t returns_filled = 0;

/// counts of memory writes and syscalls per function invocation
uint64_t write_syscall_counts[MAX_RETURNS];
size_t write_syscall_counts_index = 0;
size_t write_syscall_counts_filled = 0;

/// switches between memory writes and syscalls
bool flags[MAX_SYSCALLS + MAX_WRITES];
size_t flags_index = 0;
size_t flags_filled = 0;

/// syscall numbers, parameters, and return values
uint64_t syses[MAX_SYSCALLS];
size_t syses_index = 0;
size_t syses_filled = 0;

/// memory write destination addresses and values
uint64_t writes[MAX_WRITES];
size_t writes_index = 0;
size_t writes_filled = 0;

void mimic_write();
bool mimic_syscall();

void disabled_fn() {
  DEBUG("Entering disabled function");
  
  if (write_syscall_counts_index > write_syscall_counts_filled) {
    cerr << "Overflowing write/syscall counts array!\n";
    exit(2);
  }
  DEBUG("Popping a write/syscall count");
  uint64_t count = write_syscall_counts[write_syscall_counts_index++];
  DEBUG("There are " << count << " writes/syscalls in this function invocation");
  
  for(int i = 0; i < count; i++) {
    if (flags_index > flags_filled) {
      cerr << "Overflowing the write/syscall flags array\n";
      exit(2);
    }

    DEBUG("Popping a write/syscall flag bit");
    bool flag = flags[flags_index++];
    if(flag) {
      DEBUG("Flag is a write (" << flag << ")");
      mimic_write();
    } else {
      DEBUG("Flag is a syscall (" << flag << ")");
      if (!mimic_syscall()) {
        cerr << "Syscall mimicing failed!\n";
        exit(2);
      }
    }
  }

  if (returns_index > returns_filled) {
    cerr << "Overflowing returns array!\n";
    exit(2);
  }
  DEBUG("Popping a return registers struct");
  ret_t curr_return = returns[returns_index++];
  DEBUG("Return registers flag: " << curr_return.flag);
  
  if(curr_return.flag & 0b00001000) { DEBUG("XMM1: " << curr_return.xmm1[0] << ", " << curr_return.xmm1[1] << ", " << curr_return.xmm1[2] << ", " << curr_return.xmm1[3]); }
  if(curr_return.flag & 0b00000100) { DEBUG("XMM0: " << curr_return.xmm0[0] << ", " << curr_return.xmm0[1] << ", " << curr_return.xmm0[2] << ", " << curr_return.xmm0[3]); }
        
  if(curr_return.flag & 0b00000010) { DEBUG("RDX: " << curr_return.rdx); }
  if(curr_return.flag & 0b00000001) { DEBUG("RAX: " << curr_return.rax); }

  if(curr_return.flag & 0b00001000) asm("movdqu (%0), %%xmm1" : : "r"(curr_return.xmm1) : );
  if(curr_return.flag & 0b00000100) asm("movdqu (%0), %%xmm0" : : "r"(curr_return.xmm0) : );
  if(curr_return.flag & 0b00000010) asm("" : : "d"(curr_return.rdx) : );
  //other registers and if statements (comparison) use rax to store their values so it should come last
  if(curr_return.flag & 0b00000001) asm("" : : "a"(curr_return.rax) : );
}

//returns true upon correctly mimicing a syscall
bool mimic_syscall() {
  DEBUG("Mimicing a syscall");

  if (syses_index > syses_filled) {
    cerr << "Overflowing the syscalls array!\n";
    exit(2);
  }
  uint64_t sys_num = syses[syses_index++];

  syscall_t syscall_struct = syscalls[sys_num];
  int args_no = syscall_struct.args;

  DEBUG("Syscall " << syscall_struct.name << " (" << sys_num << "), " << args_no << " parameters");

  if (syses_index + args_no + 1 > syses_filled) { //+1 for the return
    cerr << "Overflowing the syscalls array!\n";
    exit(2);
  }

  DEBUG("Getting " << args_no << " parameters");
  uint64_t param_regs[6];
  for (int i = 0; i < args_no; i++) {
    DEBUG("Parameter " << i << " is " << syses[syses_index]);
    param_regs[i] = syses[syses_index++];
  }

  DEBUG("Setting up and making syscall");
  
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

  uint64_t original_ret = syses[syses_index++];

  // using a macro causes this to not work with mmap for some reason
  fprintf(stderr, "Finished mimicing a syscall, expected %lx, got %lx\n", original_ret, curr_ret);
  return original_ret == curr_ret; 
}

void mimic_write() {
  DEBUG("Mimicing a memory write");
  if (writes_index + 1 > writes_filled) { // + 1 for value
    cerr << "Overflowing the writes array\n";
    exit(2);
  }

  DEBUG("Getting the memory destination");
  uint64_t* memory_dest = (uint64_t*) writes[writes_index++];
  DEBUG("Getting the value at destination " << memory_dest);
  uint64_t val = writes[writes_index++];
  DEBUG("The value at " << memory_dest << " is " << val);

  *memory_dest = val;
  DEBUG("Finished mimicing a write");
}

void read_syscalls(){
  DEBUG("Reading in syscalls");
  uint64_t buffer; 
  while(sys_file.read((char*) &buffer, sizeof(uint64_t))){
    if (syses_filled >= MAX_SYSCALLS) {
      cerr << "Overflowing the syscalls array!\n";
      exit(2);
    }

    DEBUG("Read the syscall number " << buffer);
    syses[syses_filled++] = buffer;
    uint64_t num_params = syscalls[buffer].args;
    DEBUG("Syscall " << syscalls[buffer].name << " has " << num_params << " parameters");
    if (syses_filled + num_params + 1 >= MAX_SYSCALLS) { // +1 for return
      cerr << "Overflowing the syscalls array!\n";
      exit(2);
    }

    DEBUG("Reading " << num_params << " parameters");
    for (int i = 0; i < num_params; i++) {
      sys_file.read((char*) &buffer, sizeof(uint64_t));
      DEBUG("Read in parameter " << i << ":" << buffer);
      syses[syses_filled++] = buffer;
    }
    DEBUG("Reading the syscall return value");
    sys_file.read((char*) &buffer, sizeof(uint64_t));
    DEBUG("Read the return value: " << buffer);
    syses[syses_filled++] = buffer;
  }

  DEBUG("Finished reading in syscalls");
}


//first log memory address
//second log value at the mem address (both uint64_t)
void read_writes() {
  DEBUG("Reading in writes");
  
  uint64_t buffer;
  while (write_file.read((char*) &buffer, sizeof(uint64_t))) {
    if (writes_filled >= MAX_WRITES) {
      cerr << "Overflowing the writes array!\n";
      exit(2);
    }
    DEBUG("Read in write data: " << hex << buffer);
    writes[writes_filled++] = buffer;
  }

  DEBUG("Finished reading in writes");
}

//first log number of writes
//second log return struct

void read_returns() {
  DEBUG("Reading in returns");
  
  uint64_t write_sys_count;
  while(return_file.read((char*) &write_sys_count, sizeof(uint64_t))) {
    DEBUG("Read write/syscall count: " << write_sys_count);

    if (write_syscall_counts_filled >= MAX_RETURNS) {
      cerr << "Overflowing write/syscall count array!\n";
      exit(2);
    }
    write_syscall_counts[write_syscall_counts_filled++] = write_sys_count; 

    DEBUG("Reading write/syscall flag");
    for (int i = 0; i < (write_sys_count/8) + 1; i++) {
      uint8_t buf;
      DEBUG("Reading in a byte");
      return_file.read((char*) &buf, sizeof(uint8_t));

      bitset<8> byte(buf); 
      for (int j = 0; j < 8; j++) {
        if (flags_filled >= (MAX_RETURNS + MAX_SYSCALLS)) {
          cerr << "Overflowing write/syscall flag array!\n";
          exit(2);
        }
        flags[flags_filled++] = byte.test(j);
      }
      DEBUG("Processed byte: " << byte);
    }    

    ret_t return_struct;
    DEBUG("Reading return registers flag");
    return_file.read((char*) &return_struct.flag, 1);
    DEBUG("Flag is: " << return_struct.flag);

    if(return_struct.flag & 0b00000001) {
      DEBUG("Reading RAX");
      return_file.read((char*) &return_struct.rax, 8);
      DEBUG("RAX is " << hex << return_struct.rax);
    }
    if(return_struct.flag & 0b00000010) {
      DEBUG("Reading RDX");
      return_file.read((char*) &return_struct.rdx, 8);
      DEBUG("RDX is " << hex << return_struct.rdx);
    }

    if(return_struct.flag & 0b00000100) {
      DEBUG("Reading XMM0");
      for (int i = 0; i < 4; i ++) return_file.read((char*) &return_struct.xmm0[i], 4);
      DEBUG("XMM0 is " << return_struct.xmm0[0] << ", " << return_struct.xmm0[1] << ", " << return_struct.xmm0[2] << ", " << return_struct.xmm0[3]);
    }

    if(return_struct.flag & 0b00001000) {
      DEBUG("Reading XMM1");
      for (int i = 0; i < 4; i ++) return_file.read((char*) &return_struct.xmm1[i], 4);
      DEBUG("XMM1 is " << return_struct.xmm1[0] << ", " << return_struct.xmm1[1] << ", " << return_struct.xmm1[2] << ", " << return_struct.xmm1[3]);
    }

    if (returns_filled >= MAX_RETURNS) {
      cerr << "Overflowing the return registers array!\n";
      exit(2);
    }
                
    returns[returns_filled++] = return_struct;
  }

  DEBUG("Finished reading from the return log");
        
  uint64_t page_start = func_address & ~(PAGE_SIZE-1) ;
  
  DEBUG("Making the start of the page readable, writable, and executable");
  //making the page writable, readable and executable
  if (mprotect((void*) page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
    cerr << "mprotect failed: " << strerror(errno) << "\n";
    exit(2); 
  }

  DEBUG("Setting up jump from " << hex << func_address << " to " << hex << disabled_fn);
  new((void*)func_address)X86Jump((void*)disabled_fn);

  DEBUG("Finished reading returns");
}

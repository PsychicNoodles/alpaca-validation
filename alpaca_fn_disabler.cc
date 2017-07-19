#include "alpaca_shared.hh"

#include "elf++.hh"
#include "x86jump.h"

#include <arpa/inet.h>
#include <bitset>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <link.h>
#include <ucontext.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <iostream>

#define PAGE_SIZE 4096
#define NO_OVERLAPS {false, false, false, false, false, false, false, false}

using namespace std;

typedef struct {
  uint8_t flag;
  uint64_t rax;
  uint64_t rdx;
  float xmm0[4];
  float xmm1[4]; 
} ret_t; 

// queues

///return addresses
uint64_t ret_addrs[MAX_RETURNS];
size_t ret_addrs_index = 0;
size_t ret_addrs_filled = 0;

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
  DEBUG_CRITICAL("Entering disabled function");
  
  if (write_syscall_counts_index >= write_syscall_counts_filled) {
    cerr << "Overflowing write/syscall counts array at " << write_syscall_counts_index << " (cap: " << write_syscall_counts_filled << ")!\n";
    exit(2);
  }
  DEBUG("Popping a write/syscall count");
  uint64_t count = write_syscall_counts[write_syscall_counts_index++];
  DEBUG("There are " << count << " writes/syscalls in this function invocation");
  
  for(int i = 0; i < count; i++) {
    if (flags_index >= flags_filled) {
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

  if (returns_index >= returns_filled) {
    cerr << "Overflowing returns array!\n";
    exit(2);
  }
  DEBUG("Popping a return registers struct");
  ret_t curr_return = returns[returns_index++];
  DEBUG("Return registers flag: " << (int)curr_return.flag);
  
  if(curr_return.flag & 0b00001000) { DEBUG("XMM1: " << int_to_hex(curr_return.xmm1[0]) << ", " << int_to_hex(curr_return.xmm1[1])
                                            << ", " << int_to_hex(curr_return.xmm1[2]) << ", " << int_to_hex(curr_return.xmm1[3])); }
  if(curr_return.flag & 0b00000100) { DEBUG("XMM0: " << int_to_hex(curr_return.xmm0[0]) << ", " << int_to_hex(curr_return.xmm0[1])
                                            << ", " << int_to_hex(curr_return.xmm0[2]) << ", " << int_to_hex(curr_return.xmm0[3])); }
        
  if(curr_return.flag & 0b00000010) { DEBUG("RDX: " << int_to_hex(curr_return.rdx)); }
  if(curr_return.flag & 0b00000001) { DEBUG("RAX: " << int_to_hex(curr_return.rax)); }

  DEBUG_CRITICAL("Setting return registers and exiting disabled function");

  if(curr_return.flag & 0b00001000) asm("movdqu (%0), %%xmm1" : : "r"(curr_return.xmm1) : );
  if(curr_return.flag & 0b00000100) asm("movdqu (%0), %%xmm0" : : "r"(curr_return.xmm0) : );
  if(curr_return.flag & 0b00000010) asm("" : : "d"(curr_return.rdx) : );
  //other registers and if statements (comparison) use rax to store their values so it should come last
  if(curr_return.flag & 0b00000001) asm("" : : "a"(curr_return.rax) : );
}

//returns true upon correctly mimicing a syscall
bool mimic_syscall() {
  DEBUG("Mimicing a syscall");

  if (syses_index >= syses_filled) {
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
  while(sys_file.read((char*) &buffer, sizeof(uint64_t))) {
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
    DEBUG("Read in write data: " << int_to_hex(buffer));
    writes[writes_filled++] = buffer;
  }

  DEBUG("Finished reading in writes");
}

void check_bytes(uint8_t* addr, uint8_t expected[8], uint8_t* cmp_addr, bool overlaps[8], int index) {
  DEBUG("Checking bytes for " << int_to_hex((uint64_t)addr) << " at ind " << index << " with write to "
                              << int_to_hex((uint64_t)cmp_addr) << " (expected: " << int_to_hex((uint64_t)expected) << ")");

  uint8_t* ptr = addr;
  for(int i = 0; i < 8; i++) {
    DEBUG("Checking byte " << int_to_hex((uint64_t)ptr) << " (" << i << ")");
    if(overlaps[i]) {
      DEBUG("Already overlaps, skipping");
    } else if(ptr >= cmp_addr && ptr < cmp_addr + 8) { // bytes overlap
      DEBUG("Marking as overlapping");
      overlaps[i] = true;
    } else {
      DEBUG("Does not overlap, skipping");
    }
    ptr++;
  }
  DEBUG("Finished checking bytes");
}

bool cmp_bytes(uint8_t* address, uint8_t* expected, bool overlaps[8]) {
  bool diff = false;
  for(int i = 0; i < 8; i++) {
    DEBUG("Checking byte " << i << " (" << int_to_hex((uint64_t)&address[i]) << ")");
    if(overlaps[i]) {
      DEBUG("Overlaps, skipping");
    } else if(address[i] != expected[i]) {
      DEBUG("Different write detected at address " << int_to_hex((uint64_t)&address[i]) << " as part write to " << int_to_hex((uint64_t)address)
                                                   << " (expected: " << int_to_hex(expected[i]) << "; found: " << int_to_hex(address[i]) << ")");
      diff = true;
      wrong_writes++;
    } else {
      DEBUG("Byte is identical to memory");
    }
  }
  return diff;
}

bool check_write(int index, int num_writes, ucontext_t* context) {
   DEBUG("Checking nth write: " << ((writes_index + (index * 2)) / 2) << " (nth in fn call: " << index << ")");
   DEBUG("RAX is: " << int_to_hex(context->uc_mcontext.gregs[REG_RAX]));
   uint8_t* address = (uint8_t*) writes[writes_index + (index*2)];
   uint8_t* expected = (uint8_t*) &writes[writes_index + (index*2) + 1];
   uint64_t expected64 = *((uint64_t*)expected);
   bool overlaps[8] = {false};

   DEBUG("Write is to " << int_to_hex((uint64_t)address) << " with expected value " << int_to_hex(expected64));
   for(int i = 0; i < 8; i++) {
     DEBUG("expected[" << i << "]: " << int_to_hex(expected[i]));
   }

   DEBUG("Comparing with later writes");
   uint8_t* cmp_addr;
   for (int i = num_writes-1; i > index; i--) {
     DEBUG("Comparing with write " << i);
     cmp_addr = (uint8_t*)writes[writes_index + i * 2];
     DEBUG("The comparison address range is " << int_to_hex((uint64_t)cmp_addr) << " to " << int_to_hex((uint64_t)cmp_addr + 8));
     //no overlap 
     if((address < cmp_addr && address + 8 < cmp_addr) || (address > cmp_addr + 8 && address + 8 > cmp_addr + 8)) {
       DEBUG("There is no overlap, skipping");
     }
     else check_bytes(address, expected, cmp_addr, overlaps, i);
   }
   DEBUG("Finished comparing with later writes, comparing with actual memory values");

   bool diff = cmp_bytes(address, expected, overlaps);

   if(!diff) {
     DEBUG("Identical writes to " << int_to_hex((uint64_t)address) << "(" << int_to_hex(expected64) << ")");
   }
   DEBUG("***");
   return diff;
}

bool check_return(ucontext_t* context) {
  DEBUG("Checking nth return registers: " << returns_index);
  if (returns_index >= returns_filled) {
    cerr << "Overflowing returns array!\n";
    exit(2);
  }
  DEBUG("Popping a return registers struct");
  ret_t curr_return = returns[returns_index++];
  DEBUG("Return registers flag: " << (int)curr_return.flag);

  if(curr_return.flag & 0b00000001) { DEBUG("RAX: " << int_to_hex(curr_return.rax)); }
  if(curr_return.flag & 0b00000010) { DEBUG("RDX: " << int_to_hex(curr_return.rdx)); }
  if(curr_return.flag & 0b00000100) { DEBUG("XMM0: " << int_to_hex(curr_return.xmm0[0]) << ", " << int_to_hex(curr_return.xmm0[1])
                                            << ", " << int_to_hex(curr_return.xmm0[2]) << ", " << int_to_hex(curr_return.xmm0[3])); }
  if(curr_return.flag & 0b00001000) { DEBUG("XMM1: " << int_to_hex(curr_return.xmm1[0]) << ", " << int_to_hex(curr_return.xmm1[1])
                                            << ", " << int_to_hex(curr_return.xmm1[2]) << ", " << int_to_hex(curr_return.xmm1[3])); }
  
  DEBUG("Comparing registers");
  bool diff = false;
  if(curr_return.flag & 0b00000001 && context->uc_mcontext.gregs[REG_RAX] != curr_return.rax) {
    DEBUG("Different RAX value detected (expected: " << int_to_hex(curr_return.rax) << "; found: " << int_to_hex(context->uc_mcontext.gregs[REG_RAX]) << ")");
    diff = true;
  } else {
    DEBUG("Identical RAX values (" << int_to_hex(curr_return.rax) << ")");
  }
  if(curr_return.flag & 0b00000010 && context->uc_mcontext.gregs[REG_RDX] != curr_return.rdx) {
    DEBUG("Different RDX value detected (expected: " << int_to_hex(curr_return.rdx) << "; found: " << int_to_hex(context->uc_mcontext.gregs[REG_RDX]) << ")");
    diff = true;
  } else {
    DEBUG("Identical RDX values (" << int_to_hex(curr_return.rdx) << ")");
  }
  if(curr_return.flag & 0b00000100 && memcmp(context->uc_mcontext.fpregs->_xmm[0].element, curr_return.xmm0, sizeof(float) * 4) != 0) {
    float* xmm0 = (float*) context->uc_mcontext.fpregs->_xmm[0].element;
    DEBUG("Different XMM0 value detected (expected: " << int_to_hex(curr_return.xmm0[0]) << ", " << int_to_hex(curr_return.xmm0[1])
                                                      << ", " << int_to_hex(curr_return.xmm0[2]) << ", " << int_to_hex(curr_return.xmm0[3])
                                                      << "; found: " << int_to_hex(xmm0[0]) << ", " << int_to_hex(xmm0[1])
                                                      << ", " << int_to_hex(xmm0[2]) << ", " << int_to_hex(xmm0[3]) << ")");
    diff = true;
  } else {
    DEBUG("Identical XMM0 values (" << int_to_hex(curr_return.xmm0[0]) << ", " << int_to_hex(curr_return.xmm0[1])
                                    << ", " << int_to_hex(curr_return.xmm0[2]) << ", " << int_to_hex(curr_return.xmm0[3]) << ")");
  }
  if(curr_return.flag & 0b00001000 && memcmp(context->uc_mcontext.fpregs->_xmm[1].element, curr_return.xmm1, sizeof(float) * 4) != 0) {
    float* xmm1 = (float*) context->uc_mcontext.fpregs->_xmm[1].element;
    DEBUG("Different XMM0 value detected (expected: " << int_to_hex(curr_return.xmm1[0]) << ", " << int_to_hex(curr_return.xmm1[1])
                                                      << ", " << int_to_hex(curr_return.xmm1[2]) << ", " << int_to_hex(curr_return.xmm1[3])
                                                      << "; found: " << int_to_hex(xmm1[0]) << ", " << int_to_hex(xmm1[1])
                                                      << ", " << int_to_hex(xmm1[2]) << ", " << int_to_hex(xmm1[3]) << ")");
    diff = true;
  } else {
    DEBUG("Identical XMM1 values (" << int_to_hex(curr_return.xmm1[0]) << ", " << int_to_hex(curr_return.xmm1[1])
                                    << ", " << int_to_hex(curr_return.xmm1[2]) << ", " << int_to_hex(curr_return.xmm1[3]) << ")");
  }

  DEBUG("Finished checking return registers");
  return diff;
}

void trap_ret_addrs(){
  DEBUG("Setting up trap handlers for return addresses");
  for (int i = 0; i < ret_addrs_filled; i++) {
    uint64_t address = ret_addrs[i];
    DEBUG("Setting up trap handler at the return instruction: " << int_to_hex(address));
    single_step(address);
  }
  DEBUG("Finished setting up trap handlers for return addresses");
}

void check_trap_handler(int signal, siginfo_t* info, void* cont) {
  DEBUG("Check trap handler triggered");
  if (signal != SIGTRAP) {
    cerr << "Signal received was not a SIGTRAP: " << signal << "\n";
    exit(2);
  }

  ucontext_t* context = reinterpret_cast<ucontext_t*>(cont);

  DEBUG("%r13: " << int_to_hex(*(uint64_t*)context->uc_mcontext.gregs[REG_R13]));
  if (write_syscall_counts_index >= write_syscall_counts_filled) {
     cerr << "Overflowing write/syscall counts array at " << write_syscall_counts_index << " (cap: " << write_syscall_counts_filled << ")!\n";
     exit(2);
  }
  
  DEBUG("Popping a write/syscall count");
  uint64_t count = write_syscall_counts[write_syscall_counts_index++];
  DEBUG("There are " << count << " writes/syscalls in this function invocation");

  if (flags_index + count > flags_filled) {
    cerr << "Overflowing the write/syscall flags array (flags_index: " << flags_index << ", flags_filled: " << flags_filled << ")\n";
    exit(2);
  }

  DEBUG("Counting writes in the flag");
  int num_writes = 0;
  for (int i = 0; i < count; i++) {
     if (flags[flags_index + i]) num_writes++;
  }  
  DEBUG("There are " << num_writes << " writes in the flag");

  if (writes_index + num_writes * 2 > writes_filled) {
    cerr << "Overflowing the writes array (writes_index: " << writes_index << ", writes_filled: " << writes_filled << ")\n";
    exit(2);
  }

  uint8_t* address = (uint8_t*) writes[writes_index + (num_writes*2) - 2];
  uint8_t* expected = (uint8_t*) &writes[writes_index + (num_writes*2) - 1];

  if (count > 0) {
    DEBUG("Checking last write");
    bool none[8] = NO_OVERLAPS;
    if(cmp_bytes(address, expected, none)) {
      DEBUG("First write did not pass!");
    } else {
      DEBUG("First write passed, checking remaining writes");
      for(int i = num_writes - 2; i >= 0; i--) {
              if (check_write(i, num_writes, context)) DEBUG("Writes did not pass!");
      }
    }
  } else {
    DEBUG("No writes!");  
  }
  
  DEBUG("Finished checking writes");

  flags_index += count;
  writes_index += num_writes * 2;
  
  if(check_return(context)) DEBUG("Returns did not pass!");

  context->uc_mcontext.gregs[REG_RIP] = *((uint64_t*)context->uc_mcontext.gregs[REG_RSP]);
  context->uc_mcontext.gregs[REG_RSP] += 8; 

  DEBUG("Finished check trap handler");
}

//ret addr logging
void read_ret_addrs() {
  DEBUG("Reading in return addresses");
  
  uint64_t buffer;
  while(ret_addr_file.read((char*)&buffer, sizeof(uint64_t))) {
    if (ret_addrs_index >= MAX_RETURNS) {
       cerr << "Overflowing the return address array!\n";
       exit(2);    
    }
    DEBUG("Read in return address data: " << int_to_hex(buffer));
    ret_addrs[ret_addrs_filled++] = buffer;
  }

  trap_ret_addrs();

  DEBUG("Finished reading in return addresses");
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
      for (int j = 0; j < 8 && j + i * 8 < write_sys_count; j++) {
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
    DEBUG("Flag is: " << (int)return_struct.flag);

    if(return_struct.flag & 0b00000001) {
      DEBUG("Reading RAX");
      return_file.read((char*) &return_struct.rax, 8);
      DEBUG("RAX is " << int_to_hex(return_struct.rax));
    }
    if(return_struct.flag & 0b00000010) {
      DEBUG("Reading RDX");
      return_file.read((char*) &return_struct.rdx, 8);
      DEBUG("RDX is " << int_to_hex(return_struct.rdx));
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
  
  DEBUG("Finished reading returns");
}

void setup_disabler_jump() {
   DEBUG("Setting up jump for disabler from " << int_to_hex((uint64_t) func_address) << " to " << int_to_hex((uint64_t) disabled_fn));
   new((void*)func_address)X86Jump((void*)disabled_fn);
   DEBUG("Finished setting up jump for disabler");
}

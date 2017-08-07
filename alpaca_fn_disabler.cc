#include "alpaca_shared.hh"

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
#define LOCAL_SYSCALL_BUF_SIZE 1024
#define NUM_SYSCALL_PARAMS 6

using namespace std;

typedef struct {
  uint8_t flag;
  uint64_t rax;
  uint64_t rdx;
  float xmm0[4];
  float xmm1[4]; 
} ret_t;

typedef struct {
  int syscall_num;
  uint64_t params[NUM_SYSCALL_PARAMS];
  uint64_t ret_val;
} sys_t;

typedef struct {
  uint64_t syscall_ind;
  uint64_t buf_size;
  uint8_t buffer[LOCAL_SYSCALL_BUF_SIZE];
} local_sys_t;

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
sys_t syses[MAX_SYSCALLS];
size_t syses_index = 0;
size_t syses_filled = 0;

/// local syscall buffers
local_sys_t local_syses[MAX_SYSCALLS];
size_t local_syses_index = 0;
size_t local_syses_filled = 0;

/// memory write destination addresses and values
uint64_t writes[MAX_WRITES];
size_t writes_index = 0;
size_t writes_filled = 0;

// start bytes of 0xCC interrupted syscalls
uint8_t start_bytes[MAX_SYSCALLS + MAX_RETURNS];
size_t start_bytes_index = 0;
size_t start_bytes_filled = 0;

uint64_t* stack_base2; //the beginning of the stack for the targeted function

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
            cerr << "Overflowing the write/syscall flags array (flags_index: " << flags_index << ", flags_filled: " << flags_filled << ")\n";
      exit(2);
    }

    DEBUG("Popping a write/syscall flag bit (flags_index: " << flags_index << ")");
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
    DEBUG("Finished write/syscall " << i);
  }

  if (returns_index >= returns_filled) {
    cerr << "Overflowing returns array!\n";
    exit(2);
  }
  DEBUG("Popping a return registers struct");
  ret_t curr_return = returns[returns_index++];
  DEBUG("Return registers flag: " << (int)curr_return.flag);
  
  if(curr_return.flag & 0b00001000) {
          DEBUG("XMM1: " << curr_return.xmm1[0] << ", " << curr_return.xmm1[1]
                         << ", " << curr_return.xmm1[2] << ", " << curr_return.xmm1[3]);
          for(int i = 0; i < 4; i++) {
                  for(int j = 0; j < 4; j++) {
                          uint8_t* bytes = (uint8_t*) &curr_return.xmm1;
                          DEBUG("XMM1 part " << i << " at " << j << " is " << int_to_hex((uint64_t)bytes[i]));
                  }
          }
  }
  if(curr_return.flag & 0b00000100) {
          DEBUG("XMM0: " << curr_return.xmm0[0] << ", " << curr_return.xmm0[1]
                         << ", " << curr_return.xmm0[2] << ", " << curr_return.xmm0[3]);
          for(int i = 0; i < 4; i++) {
                  for(int j = 0; j < 4; j++) {
                          uint8_t* bytes = (uint8_t*) &curr_return.xmm0;
                          DEBUG("XMM0 part " << i << " at " << j << " is " << int_to_hex((uint64_t)bytes[i]));
                  }
          }
  }
        
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
  DEBUG("Mimicing a syscall (" << syses_index << "th syscall)");

  if (syses_index >= syses_filled) {
    cerr << "Overflowing the syscalls array!\n";
    exit(2);
  }

  bool local_syscall;
  if(local_syses_index <= local_syses_filled) {
    DEBUG("Checking next local syscall (" << local_syses[local_syses_index].syscall_ind << "th syscall/write)");
    local_syscall = local_syses[local_syses_index].syscall_ind == syses_index;
  } else {
    DEBUG("No more local syscalls");
    local_syscall = false;
  }

  sys_t sys = syses[syses_index++];

  syscall_t syscall_struct = syscalls[sys.syscall_num];
  int args_no = syscall_struct.args;

  DEBUG("Syscall " << syscall_struct.name << " (" << sys.syscall_num << "), " << args_no << " parameters");

  if (syses_index > syses_filled) { //+1 for the return
    cerr << "Overflowing the syscalls array!\n";
    exit(2);
  }

  DEBUG("Getting " << args_no << " parameters");
  for (int i = 0; i < args_no; i++) {
    DEBUG("Parameter " << i << " is " << sys.params[i]);
  }

  if(local_syscall) {
    DEBUG("Mimicing local syscall"); 
    if(sys.syscall_num == 1) {
      DEBUG("Local write syscall");
      sys.params[1] = (uint64_t) local_syses[local_syses_index].buffer;
    }
    local_syses_index++;
  }

  DEBUG("Setting up and making syscall");
  
  if (args_no > 0) asm("mov %0, %%rdi" : : "r"(sys.params[0]) : );
  if (args_no > 3) asm("mov %0, %%r10" : : "r"(sys.params[3]) : );
  if (args_no > 4) asm("mov %0, %%r8" : : "r"(sys.params[4]) : );
  if (args_no > 5) asm("mov %0, %%r9" : : "r"(sys.params[5]) : );
  if (args_no > 1) asm("mov %0, %%rsi" : : "r"(sys.params[1]) : );
  if (args_no > 2) asm("mov %0, %%rdx" : : "r"(sys.params[2]) : );

  //calling
  asm("mov %0, %%rax; syscall": : "r" ((uint64_t)sys.syscall_num):);
 
  uint64_t curr_ret;
  asm("mov %%rax, %0": "=r" (curr_ret): :);

  // using a macro causes this to not work with mmap for some reason
  fprintf(stderr, "Finished mimicing a syscall, expected %lx, got %lx\n", sys.ret_val, curr_ret);
  return sys.ret_val == curr_ret; 
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
  DEBUG("Write " << int_to_hex(val) << " to "<< int_to_hex((uint64_t)memory_dest));

  for (int i = 0; i < 8; i++) {
    DEBUG("Byte " << i << ": " << int_to_hex((uint64_t)((uint8_t*)&val)[i]));
  }

  *memory_dest = val;
  DEBUG("Finished mimicing a write");
}

void read_syscalls(){
  DEBUG("Reading in syscalls");
  uint64_t buffer; 
  while(fread((char*) &buffer, sizeof(uint64_t), 1, sys_file)) {
    if (syses_filled >= MAX_SYSCALLS) {
      cerr << "Overflowing the syscalls array!\n";
      exit(2);
    }

    DEBUG("Read the syscall number " << buffer);
    sys_t sys;
    sys.syscall_num = buffer;
    uint64_t num_params = syscalls[buffer].args;
    DEBUG("Syscall " << syscalls[buffer].name << " has " << num_params << " parameters");
    if (syses_filled >= MAX_SYSCALLS) { // +1 for return
      cerr << "Overflowing the syscalls array!\n";
      exit(2);
    }

    memset(sys.params, NUM_SYSCALL_PARAMS, sizeof(uint64_t));
    DEBUG("Reading " << num_params << " parameters");
    for (int i = 0; i < num_params; i++) {
      fread((char*) &buffer, sizeof(uint64_t), 1, sys_file);
      DEBUG("Read in parameter " << i << ":" << buffer);
      sys.params[i] = buffer;
    }
    DEBUG("Reading the syscall return value");
    fread((char*) &buffer, sizeof(uint64_t), 1, sys_file);
    DEBUG("Read the return value: " << buffer);
    sys.ret_val = buffer;

    syses[syses_filled++] = sys;
  }

  DEBUG("Finished reading in syscalls");
}

void read_local_syscalls() {
  DEBUG("Reading in local syscall buffers");
  uint64_t buffer;
  while(fread((char*) &buffer, sizeof(uint64_t), 1, local_sys_file)) {
    if (local_syses_filled >= MAX_SYSCALLS) {
      cerr << "Overflowing the local syscall buffers array!\n";
      exit(2);
    }
    
    DEBUG("Read the syscall index " << buffer);
    local_syses[local_syses_filled].syscall_ind = buffer;

    DEBUG("Reading the buffer size");
    fread((char*) &buffer, sizeof(uint64_t), 1, local_sys_file);
    DEBUG("Read the buffer size: " << buffer);
    local_syses[local_syses_filled].buf_size = buffer;

    DEBUG("Reading in " << buffer << " bytes into the buffer");
    fread(local_syses[local_syses_filled].buffer, 1, buffer, local_sys_file);
    DEBUG("Read in buffer");

    local_syses_filled++;
  }

  DEBUG("Finished reading in local syscall buffers");
}


//first log memory address
//second log value at the mem address (both uint64_t)
void read_writes() {
  DEBUG("Reading in writes");
  
  uint64_t buffer;
  while (fread((char*) &buffer, sizeof(uint64_t), 1, write_file)) {
    if (writes_filled >= MAX_WRITES) {
      cerr << "Overflowing the writes array!\n";
      exit(2);
    }
    DEBUG("Read in write data: " << int_to_hex(buffer));
    writes[writes_filled++] = buffer;
  }

  DEBUG("Finished reading in writes");
}

void trap_register_handler(int signal, siginfo_t* info, void* cont) {
  DEBUG("Trap handler triggered");
  if (signal != SIGTRAP) {
    cerr << "Signal received was not a SIGTRAP: " << signal << "\n";
    exit(2);
  }

  //used to keep track of the stack manipulation 
  static bool first_run = true;
  static bool return_reached = false;
  static int call_count = 0;
  static ud_t ud_obj;
  static bool non_regular_start = false;

  static uint8_t* instr_first_byte = (uint8_t*)func_address;
  static unsigned int function_start_counter = 0;
  static uint64_t ret_addr = 0; //ret addr logging 
  
  uint64_t* rsp;

  ucontext_t* context = reinterpret_cast<ucontext_t*>(cont);

  debug_registers(context);

  if (start_byte == 0x55) {
    if (first_run) {
      DEBUG_CRITICAL("Target function called (" << function_start_counter++ << ")");
      
      DEBUG("Function starting byte is 0x55");
      DEBUG("Initializing stack base");
      //Faking the %rbp stack push to account for the 0xCC byte overwrite
      stack_base2 = (uint64_t*)context->uc_mcontext.gregs[REG_RSP];
      uint64_t frame = (uint64_t)context->uc_mcontext.gregs[REG_RBP];

      DEBUG("Stack base is " << stack_base2);

      stack_base2--;
      *stack_base2 = frame;
      context->uc_mcontext.gregs[REG_RSP] = (uint64_t)stack_base2;

      initialize_ud(&ud_obj);

      first_run = false;
      instr_first_byte[0] = start_byte;
    }
  }  else {
    non_regular_start = true;
    DEBUG("Function starting byte is irregular: " << int_to_hex(start_byte));
    
    
    if (first_run) {
      DEBUG_CRITICAL("Target function called (" << function_start_counter++ << ")");
      
      DEBUG("Subtracted RIP with value " << int_to_hex(context->uc_mcontext.gregs[REG_RIP]) << " to account for the 0xCC overwrite");

      stack_base2 = (uint64_t*)context->uc_mcontext.gregs[REG_RSP];
      DEBUG("Stack base is " << int_to_hex((uint64_t) stack_base2));

      instr_first_byte[0] = start_byte; //save the original byte
      DEBUG("Restoring " << int_to_hex(start_byte) << " to first byte " << int_to_hex((uint64_t) instr_first_byte));
      context->uc_mcontext.gregs[REG_RIP]--; //rerun the current instruction 
      
      initialize_ud(&ud_obj);
      first_run = false;

    }
  }

  //if end of a function is reached in the next step  
  if (return_reached) {
    DEBUG("The last instruction was a return");
    call_count--;
    return_reached = false;

    if(call_count < 0) {
      DEBUG_CRITICAL("The target function has returned");
      
      DEBUG("Stopping single stepping");
      //stops single-stepping
      context->uc_mcontext.gregs[REG_EFL] &= ~(1LL << 8);

      DEBUG("Enabling single step once the target function is called again");
      start_byte = single_step(func_address);
      
      DEBUG("Resetting static variables");
      // reset for next time target function is called
      non_regular_start = false; 
      first_run = true;
      call_count = 0;

      DEBUG("Finished resetting static variables");

     return;
    }
  }

  DEBUG("Setting input buffer");
  //grabs next instruction to disassemble 
  ud_set_input_buffer(&ud_obj, (uint8_t*) context->uc_mcontext.gregs[REG_RIP], 18);
  DEBUG("Input set, disassembling");
  ud_disassemble(&ud_obj);
  DEBUG("Instruction disassembled");

  DEBUG("Instruction at " << int_to_hex(context->uc_mcontext.gregs[REG_RIP]) << ": " << ud_insn_asm(&ud_obj));
  
  switch (ud_insn_mnemonic(&ud_obj)) {
  case UD_Iret: case UD_Iretf:
    DEBUG("Special case: ret (call count is " << call_count << ")");
    ret_addr = context->uc_mcontext.gregs[REG_RIP]; //ret addr logging
    rsp = (uint64_t*) context->uc_mcontext.gregs[REG_RSP];
    DEBUG("Will return to " << int_to_hex(*rsp) << " (" << int_to_hex((uint64_t) rsp) << ")");
    return_reached = true;
    break;
  case UD_Icall:
    DEBUG("Special case: call");
    call_count++;
    break;
  default:
    break;
  }

  DEBUG("Continuing to single step");
  //set TRAP flag to continue single-stepping
  context->uc_mcontext.gregs[REG_EFL] |= 1 << 8;

  DEBUG("Finished trap handler");
}

void check_bytes(uint8_t* addr, uint8_t expected[8], uint8_t* cmp_addr, bool overlaps[8], int index) {
  DEBUG("Checking bytes for " << int_to_hex((uint64_t)addr) << " with write to " << int_to_hex((uint64_t)cmp_addr)
                              << " at ind " << index << " (expected: " << int_to_hex((uint64_t)expected) << ")");

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

bool check_write(int writes_upper, int writes_lower, ucontext_t* context) {
   DEBUG("Checking nth write: " << (writes_lower * 2));
   DEBUG("RAX is: " << int_to_hex(context->uc_mcontext.gregs[REG_RAX]));
   uint8_t* address = (uint8_t*) writes[writes_lower * 2];
   uint8_t* expected = (uint8_t*) &writes[writes_lower * 2 + 1];
   uint64_t expected64 = *((uint64_t*)expected);
   bool overlaps[8] = {false};

   DEBUG("Write is to " << int_to_hex((uint64_t)address) << " with expected value " << int_to_hex(expected64));
   for(int i = 0; i < 8; i++) {
     DEBUG("expected[" << i << "]: " << int_to_hex(expected[i]));
   }

   DEBUG("Comparing with later writes");
   uint8_t* cmp_addr;
   for (int i = writes_upper; i > writes_lower; i--) {
     DEBUG("Comparing with write " << i);
     cmp_addr = (uint8_t*)writes[i * 2];
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
  DEBUG("Setting up trap handlers for return addresses and system calls");
  for (int i = 0; i < ret_addrs_filled; i++) {
    uint64_t address = ret_addrs[i];
    bool already_trapped = false;
    for(int n = 0; n < i; n++) {
      if(ret_addrs[n] == ret_addrs[i]) {
        DEBUG("Already set trap at this address (the " << n << "th trap), skipping");
        start_bytes[start_bytes_filled] = start_bytes[n];
        already_trapped = true;
        break;
      }
    }
    if(!already_trapped) {
      DEBUG("Setting up trap handler at the return/syscall instruction: " << int_to_hex(address));
      start_bytes[start_bytes_filled] = single_step(address);
    }
    start_bytes_filled++;
  }
  DEBUG("Finished setting up trap handlers for return addresses");
}

void check_trap_handler(int signal, siginfo_t* info, void* cont) {
  DEBUG("Check trap handler triggered");
  if (signal != SIGTRAP) {
    cerr << "Signal received was not a SIGTRAP: " << signal << "\n";
    exit(2);
  }

  static ud_t ud_obj;
  static bool first_run = true;
  static size_t total_func_writes = 0;
  static size_t writes_lower = 0; // saved from last syscall/return
  // syscall indices array
  static size_t sys_indices[MAX_SYSCALLS];
  static size_t sys_indices_index = 0;
  static size_t sys_indices_filled = 0;
  static bool repeat_syscall = false; 

  if(first_run) {
    initialize_ud(&ud_obj);

    //for return upper bound number of writes
    if (write_syscall_counts_index >= write_syscall_counts_filled) {
      cerr << "Overflowing write/syscall counts array at " << write_syscall_counts_index << " (cap: " << write_syscall_counts_filled << ")!\n";
      exit(2);
    }
    DEBUG("Popping a write/syscall count");
    uint64_t count = write_syscall_counts[write_syscall_counts_index++];
    DEBUG("There are " << count << " writes/syscalls in this function invocation");
    
    for(size_t i = 0; i < flags_filled; i++) {
      if (!flags[i]) {
        sys_indices[sys_indices_filled] = i;
        sys_indices_filled++; 
      } else total_func_writes++; 
    }

    for(size_t i = 0; i < sys_indices_filled; i++) DEBUG("sys_indices[" << i << "]: " << sys_indices[i]);
          for(int i = 0; i < ret_addrs_filled; i++) DEBUG("ret_addrs[" << i << "]: " << int_to_hex(ret_addrs[i]));
    
    first_run = false;
  }
  
  ucontext_t* context = reinterpret_cast<ucontext_t*>(cont);

  if (repeat_syscall) {
    single_step(context->uc_mcontext.gregs[REG_RIP] - 1);
    repeat_syscall = false;
    context->uc_mcontext.gregs[REG_EFL] &= ~(1LL << 8);
    return;
  }
  
  ret_addrs_index++;
  DEBUG("Ret_addrs index incremented; current value: " << ret_addrs_index);

  DEBUG("%r13: " << int_to_hex(*(uint64_t*)context->uc_mcontext.gregs[REG_R13]));
  context->uc_mcontext.gregs[REG_RIP]--; // move back to the trapped instruction

  uint8_t byte = start_bytes[start_bytes_index];
  bool is_return = byte == 0xc3 || byte == 0xcb; // maybe 0xc2 and 0xca too
  DEBUG("start_byte: " << int_to_hex(start_bytes[start_bytes_index]));
  
  DEBUG("At a return: " << (is_return ? "true" : "false"));
  DEBUG("Instruction at " << int_to_hex(context->uc_mcontext.gregs[REG_RIP]) << ": " << ud_insn_asm(&ud_obj));

  DEBUG("Calculating number of writes");
  DEBUG("sys_indices_index: " << sys_indices_index);

  size_t writes_upper;
  
  if (is_return) writes_upper = total_func_writes; 
  else writes_upper = sys_indices[sys_indices_index++];
  
  size_t num_writes = writes_upper - writes_lower; 
  DEBUG("The upper bound of writes is: " << writes_upper << "; the lower bound is: " << writes_lower);
  
  if (writes_index + num_writes* 2 > writes_filled) {
    cerr << "Overflowing the writes array (writes_index: " << writes_index << ", writes_filled: " << writes_filled << ", num_writes: " << num_writes << ")\n";
    exit(2);
  }

  uint8_t* address = (uint8_t*) writes[writes_index + (num_writes*2) - 2];
  uint8_t* expected = (uint8_t*) &writes[writes_index + (num_writes*2) - 1];

  DEBUG("Current write index: " << writes_index << " , num_writes: " << num_writes);
  if (num_writes > 0) {
    DEBUG("Checking last write");
    bool none[8] = NO_OVERLAPS;
    if(cmp_bytes(address, expected, none)) {
      DEBUG("First write did not pass!");
    } else {
      DEBUG("First write passed, checking remaining writes");
      if (num_writes > 1) {
        for(int i = writes_upper - 1; i >= writes_lower && i < writes_upper; i--) { //underflow, watch out
          DEBUG("i is " << i << " and write_index is " << writes_index);
          if (check_write(writes_upper, i, context)) DEBUG("Writes did not pass!");
        }
      }
    }
  } else {
    DEBUG("No writes!");  
  }
  
  DEBUG("Finished checking writes");

  writes_index += num_writes * 2;
   
  if (is_return) {
    DEBUG("Checking return values");
    if(check_return(context)) DEBUG("Returns did not pass!");

    context->uc_mcontext.gregs[REG_RIP] = *((uint64_t*)context->uc_mcontext.gregs[REG_RSP]);
    context->uc_mcontext.gregs[REG_RSP] += 8;
    start_bytes_index++; 
  } else { //putting back the original byte to perform the syscall
    ((uint8_t*)context->uc_mcontext.gregs[REG_RIP])[0] = start_bytes[start_bytes_index++];
    //if syscall is repeated, trap needs to be reinserted
    for (int i = ret_addrs_index; i < ret_addrs_filled; i++) {
      if (ret_addrs[i] == context->uc_mcontext.gregs[REG_RIP]) {
        repeat_syscall = true;
        context->uc_mcontext.gregs[REG_EFL] |= 1 << 8;
        break;
       }
    }
  }

  writes_lower = writes_upper + 1; 
  DEBUG("Saved the current writes upper bound: " << writes_upper << "; to lower bound: " << writes_lower);
  DEBUG("Finished check trap handler");
}


//ret addr logging
void read_ret_addrs() {
  DEBUG("Reading in return addresses");
  
  uint64_t buffer;
  while(fread((char*)&buffer, sizeof(uint64_t), 1, ret_addr_file)) {
    if (ret_addrs_filled >= MAX_RETURNS) {
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
  while(fread((char*) &write_sys_count, sizeof(uint64_t), 1, return_file)) {
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
      fread((char*) &buf, sizeof(uint8_t), 1, return_file);

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
    fread((char*) &return_struct.flag, 1, 1, return_file);
    DEBUG("Flag is: " << (int)return_struct.flag);

    if(return_struct.flag & 0b00000001) {
      DEBUG("Reading RAX");
      fread((char*) &return_struct.rax, 8, 1, return_file);
      DEBUG("RAX is " << int_to_hex(return_struct.rax));
    }
    if(return_struct.flag & 0b00000010) {
      DEBUG("Reading RDX");
      fread((char*) &return_struct.rdx, 8, 1, return_file);
      DEBUG("RDX is " << int_to_hex(return_struct.rdx));
    }

    if(return_struct.flag & 0b00000100) {
      DEBUG("Reading XMM0");
      for (int i = 0; i < 4; i ++) {
        uint8_t xmm0[4];
        fread((char*) xmm0, 4, 1, return_file);
        for(int j = 0; j < 4; j++) {
          DEBUG("XMM0 part " << i << " at " << j << " is " << int_to_hex((uint64_t) xmm0[j]));
        }

        return_struct.xmm0[i] = ((float*)xmm0)[0];
        DEBUG("Saved xmm0 value in return struct: "<<  ((float*)xmm0)[0]);
      }
      for(int i = 0; i < 4; i++) {
        DEBUG("XMM0 at " << i << " is " << return_struct.xmm0[i]);
      }
    }

    if(return_struct.flag & 0b00001000) {
      DEBUG("Reading XMM1");
      for (int i = 0; i < 4; i ++) {
        uint8_t xmm1[4];
        fread((char*) xmm1, 4, 1, return_file);
        for(int j = 0; j < 4; j++) {
          DEBUG("XMM1 part " << i << " at " << j << " is " << int_to_hex((uint64_t) xmm1[j]));
        }
        return_struct.xmm1[i] = ((float*)xmm1)[0];
        DEBUG("Saved xmm1 value in return struct: "<<  ((float*)xmm1)[0]);
      }
      for(int i = 0; i < 4; i++) {
        DEBUG("XMM1 at " << i << " is " << return_struct.xmm1[i]);
      }
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

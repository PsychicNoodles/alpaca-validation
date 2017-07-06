#include "alpaca_shared.hh"

//citations: modified example code from
//https://github.com/aclements/libelfin/blob/master/examples/dump-syms.cc
#include "elf++.hh" //parsing the binary file 
#include "x86jump.h" //jumping to function disabler
#include <udis86.h> //interpreting assembly instructions

#include <arpa/inet.h>
#include <bitset>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <execinfo.h>
#include <fstream>
#include <inttypes.h>
#include <link.h>
#include <new>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <ucontext.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define MAX_OPERANDS 126
#define NUM_RET_REGS 4

#define MAX_WRITE_SYSCALL_COUNT 1024 * 1024 * 1024
#define MAX_WRITE_COUNT 500

using namespace std;

uint64_t mem_writing; //the destination address of an instruction that writes
uint64_t* stack_base; //the beginning of the stack for the targeted function

//keep track of the detected writes and syscall of the function 
uint64_t write_syscall_count;

//true for write, false for syscall
bool write_syscall_flag[MAX_WRITE_SYSCALL_COUNT];

//the byte overwrtitten with 0xCC for single-stepping
uint8_t start_byte;

//registers where the return values are stored 
const ud_type_t ret_regs[NUM_RET_REGS] = {UD_R_RAX, UD_R_RDX, UD_R_XMM0, UD_R_XMM1};
const ud_type_t rax_regs[5] = {UD_R_RAX, UD_R_EAX, UD_R_AX, UD_R_AH, UD_R_AL};
const ud_type_t rdx_regs[5] = {UD_R_RDX, UD_R_EDX, UD_R_DX, UD_R_DH, UD_R_DL};
bool ret_regs_touched[NUM_RET_REGS] = {false};

//the registers where the parameters of a syscall instruction are stored
const ud_type_t syscall_params[6] = {UD_R_RDI, UD_R_RSI, UD_R_RDX, UD_R_R10, UD_R_R8, UD_R_R9};

//function declarations
uint64_t get_register(ud_type_t obj, ucontext_t* context);
uint32_t* get_fp_register(ud_type_t obj, ucontext_t* context);
void initialize_ud(ud_t* ud_obj);
bool just_read(uint64_t mem_address, bool is_mem_opr, ucontext_t* context);
void log_write(uint64_t dest_address);
void test_operand(ud_t* obj, int n);
void trap_handler(int signal, siginfo_t* info, void* cont);
void log_syscall(uint64_t sys_num, ucontext_t* context);
void log_sys_ret(uint64_t ret_value_reg);

void initialize_ud(ud_t* ud_obj) {
  DEBUG("Initializing the udis86 object");
  ud_init(ud_obj);
  ud_set_mode(ud_obj, 64);
  ud_set_syntax(ud_obj, UD_SYN_ATT);
  ud_set_vendor(ud_obj, UD_VENDOR_INTEL);
  DEBUG("Finished initializing the udis86 object");
}

/**
 * Enables single-stepping (instruction by instruction) through the function
 * func_address: (virtual) address of the function in memory
 */
void single_step(uint64_t address) {
  DEBUG("Enabling single step for the function at " << int_to_hex(address));
  uint64_t page_start = address & ~(PAGE_SIZE-1) ;

  DEBUG("Making the start of the page readable, writable, and executable");
  //making the page writable, readable and executable
  if (mprotect((void*) page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
    cerr << "mprotect failed: " << strerror(errno) << "\n";
    exit(2); 
  }

  DEBUG("Setting the first byte to 0xCC");
  //setting the first byte to 0xCC causes a SIGTRAP signal for single-stepping
  start_byte = ((uint8_t*)address)[0];
  DEBUG("Stored the original starting byte: " << int_to_hex(start_byte));
  ((uint8_t*)address)[0] = 0xCC;
  DEBUG("Finished enabling single step");
}


/**
 *Finds the destination memory address of an instruction
 */
uint64_t find_destination(const ud_operand_t* op, ucontext_t* context) {
  DEBUG("Finding the destination of instruction");
  int64_t offset; //displacement offset

  DEBUG("Size of offset: " << (int) op->offset << ", base register: " << op->base << ", index register: " << op->index);
  switch(op->offset) {
  case 8:
    DEBUG("Instruction offset is 8 bits");
    offset = (int8_t) op->lval.sbyte;
    break; 
  case 16:
    DEBUG("Instruction offset is 16 bits");
    offset = (int16_t) op->lval.sword;
    break;
  case 32:
    DEBUG("Instruction offset is 32 bits");
    offset = (int32_t) op->lval.sdword;
    break;
  case 64:
    DEBUG("Instruction offset is 64 bits");
    offset = (int64_t) op->lval.sqword;
    break;
  default:
    DEBUG("Irregular offset size (" << (int) op->offset << ")!");
    offset = 0;
  }

  size_t base = get_register(op->base, context);
  size_t index = get_register(op->index, context);
  uint8_t scale = op->scale;
  DEBUG("Offset: " << int_to_hex(offset) << ", base: " << int_to_hex(base) << ", index: " << index << ", scale: " << (int) scale);
  DEBUG("Finished finding destination: " << int_to_hex((uint64_t) (offset + base + (index * scale))));
  //calculating the memory address based on assembly register information 
  return (uint64_t) (offset + base + (index * scale)); 
}


/**
 *Detects the operand type which can be a memory or a register
 *if it is not a read only instruction than records it as a memory write
 *if it is a register and a return register then mark it as touched 
 */

void test_operand(ud_t* obj, int n, ucontext_t* context) {
  DEBUG("Testing operand " << n);
        
  const ud_operand_t* op = ud_insn_opr(obj, n);
  
  bool is_mem_opr = op->type == UD_OP_MEM;
  bool is_reg_opr = op->type == UD_OP_REG;

  DEBUG("The operand is " << (is_mem_opr ? "" : "not ") << "a memory operand");
  DEBUG("The operand is " << (is_reg_opr ? "" : "not ") << "a register operand");
  
  if (is_mem_opr) {
    uint64_t mem_address = find_destination(op, context);
    DEBUG("Found the destination memory address " << int_to_hex(mem_address));
    
    if (just_read(mem_address, is_mem_opr, context)) {
      DEBUG("Operand only reads");
    }
    else {
      DEBUG("Operand may write, saving the destination address");
      DEBUG("Address is " << int_to_hex(mem_address) << ", asm is " << ud_insn_asm(obj));
      mem_writing = mem_address;
    }
    if (op->base == UD_R_RIP) {
      DEBUG("Instruction is offset the RIP, adding the size of the instruction (" << ud_insn_len(obj) << ")");
      mem_writing += ud_insn_len(obj);
    }
  } else if (is_reg_opr) {
    DEBUG("Checking if the register operand is a return register");
    for (int i = 0; i < NUM_RET_REGS; i ++) {
      if (i == 0) {
        for (int j = 0; j < 5; j++) {
          if (op->base == rax_regs[j]) {
            DEBUG("Register operand is RAX");
            ret_regs_touched[i] = true;
          }
        }
      } else if (i == 1) {
        for (int j = 0; j < 5; j++) {
          if (op->base == rdx_regs[j]) {
            DEBUG("Register operand is RDX");
            ret_regs_touched[i] = true;
          }
        }
      } else {
        if (op->base == ret_regs[i]) {
          DEBUG("Register operand is " << (i == 2 ? "XMM0" : "XMM1"));
          ret_regs_touched[i] = true;
        }
      }
    }
  }

  DEBUG("Finished testing operand");
}

void log_returns(ucontext_t* context) {
  DEBUG("Logging returns");
  DEBUG("Logging count of writes/syscalls: " << write_syscall_count);
  return_file.write((char*) &write_syscall_count, sizeof(uint64_t));

  DEBUG("Logging write/syscall flag");
  //flag to switch between memory writes and syscalls
  bitset<8> flag_byte;
  //updates 8 bits at a time and log the flag 
  for(int i = 0; i < (write_syscall_count / 8) + 1; i++) {
    flag_byte.reset(); 
    for(int j = 0; j < 8 && j + i * 8 < write_syscall_count; j++) {
      if(write_syscall_flag[i * 8 + j]) {
        flag_byte.set(j, true);
      }
    }
    DEBUG("Write/syscall flag byte: " << flag_byte);
    return_file.write((char*)&flag_byte, 1);
  }

  uint8_t reg_flag = 0; 
  //which registers we're writing to
  for (int i = 0; i < NUM_RET_REGS; i++) {
    if (ret_regs_touched[i]) reg_flag |= (1 << i);
  }

  DEBUG("Logging register flag: " << (int) reg_flag);
  return_file.write((char*) &reg_flag, 1);

  DEBUG("Logging return registers");
  //logging the return registers
  for (int i = 0; i < NUM_RET_REGS; i++) {
    if (ret_regs_touched[i]) {
      if(i < 2) { //integer types
        uint64_t buf = get_register(ret_regs[i], context);
        DEBUG((i == 0 ? "RAX" : "RDX") << " register value: " << int_to_hex(buf));
        return_file.write((char*) &buf, 8);
      } else { //floating point types
        float* buf = (float*)get_fp_register(ret_regs[i], context);
        DEBUG((i == 2 ? "XMM0" : "XMM1") << " register values: " << int_to_hex(buf[0])
              << ", " << int_to_hex(buf[1]) << ", " << int_to_hex(buf[2]) << ", " << int_to_hex(buf[3]));
        for (int j = 0; j < 4; j++)
          return_file.write((char*) &buf[j], sizeof(float));
                                
      }
    }
  }

  DEBUG("Finished logging returns");
}



/**
 * Initially catches the SIGTRAP signal cause by INT3(0xCC) followed by catching a TRAP FLAG
 * Analyzes next instruction's effects by parsing assembly information 
 * Takes in regular signal_handler parameters when called by sigaction
 * signal: only processes SIGTRAP signal 
 * siginfo_t* info: information about the instruction which caused the signal 
 * void* cont: context of the instruction with general register informatio
 */
void trap_handler(int signal, siginfo_t* info, void* cont) {
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
  static bool waiting_syscall = false;
  static int write_count = 0;
  static uint8_t* instr_first_byte = (uint8_t*)func_address; 
  
  uint64_t* rsp;

  //logging writes
  if (mem_writing != 0) {
    if (write_count > MAX_WRITE_COUNT) {
      cerr << "maximum write count reached!\n";
      exit(2);
    }
    
    write_count++;
    DEBUG("Last instruction was a memory write to address: " << int_to_hex(mem_writing));
    log_write(mem_writing);
    mem_writing = 0;
  }
  
  ucontext_t* context = reinterpret_cast<ucontext_t*>(cont);

  //if the last instruction was a syscall then grab and log the return value
  if(waiting_syscall) {
    DEBUG("Last instruction was a syscall, gathering return value");
    log_sys_ret(context->uc_mcontext.gregs[REG_RAX]);
    waiting_syscall = false;
  }

  if (start_byte == 0x55) {
    if (first_run) {
      DEBUG_CRITICAL("Target function called");
      
      DEBUG("Function starting byte is 0x55");
      DEBUG("Initializing stack base");
      //Faking the %rbp stack push to account for the 0xCC byte overwrite
      stack_base = (uint64_t*)context->uc_mcontext.gregs[REG_RSP];
      uint64_t frame = (uint64_t)context->uc_mcontext.gregs[REG_RBP];

      DEBUG("Stack base is " << stack_base);

      stack_base--;
      *stack_base = frame;
      context->uc_mcontext.gregs[REG_RSP] = (uint64_t)stack_base;

      initialize_ud(&ud_obj);

      first_run = false;
      instr_first_byte[0] = start_byte;
    }
  }  else {
    non_regular_start = true;
    DEBUG("Function starting byte is irregular: " << int_to_hex(start_byte));
    
    
    if (first_run) {
      DEBUG_CRITICAL("Target function called");
      
      DEBUG("Subtracted RIP with value " << int_to_hex(context->uc_mcontext.gregs[REG_RIP]) << " to account for the 0xCC overwrite");

      stack_base = (uint64_t*)context->uc_mcontext.gregs[REG_RSP];
      DEBUG("Stack base is " << int_to_hex((uint64_t) stack_base));

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
      DEBUG("The target function has returned");
      
      log_returns(context);

      DEBUG("Stopping single stepping");
      //stops single-stepping
      context->uc_mcontext.gregs[REG_EFL] &= ~(1LL << 8);

      DEBUG("Enabling single step once the target function is called again");
      single_step(func_address);

      DEBUG("There were " << write_syscall_count << " writes/syscalls");
      
      DEBUG("Resetting static variables");
      // reset for next time target function is called
      non_regular_start = false; 
      first_run = true;
      call_count = 0;
      write_syscall_count = 0;
      memset(ret_regs_touched, false, NUM_RET_REGS);
      write_count = 0;

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
    rsp = (uint64_t*) context->uc_mcontext.gregs[REG_RSP];
    DEBUG("Will return to " << int_to_hex(*rsp) << " (" << int_to_hex((uint64_t) rsp) << ")");
    return_reached = true;
    break;

  case UD_Icall:
    DEBUG("Special case: call");
    call_count++;
    break;
    //readonly 1 operand instructions
  case UD_Iclflush: case UD_Iclts: case UD_Iffree: case UD_Iffreep:
  case UD_Ifld1: case UD_Ifldcw: case UD_Ifldenv: case UD_Ifldl2e:
  case UD_Ifldl2t: case UD_Ifldlg2: case UD_Ifldln2: case UD_Ifldz:
  case UD_Iftst: case UD_Ifxam: case UD_Ifxtract: case UD_Igetsec:
  case UD_Iint1: case UD_Iinto: case UD_Ijb: case UD_Ijbe: case UD_Ijecxz:
  case UD_Ijl: case UD_Ijmp: case UD_Ijae: case UD_Ija: case UD_Ijge:
  case UD_Ijno: case UD_Ijnp: case UD_Ijns: case UD_Ijnz: case UD_Ijo:
  case UD_Ijp: case UD_Ijs: case UD_Ijz: case UD_Ilahf: case UD_Ildmxcsr:
  case UD_Ileave: case UD_Inop: case UD_Ipop: case UD_Ipopfq:
  case UD_Iprefetchnta: case UD_Iprefetcht0: case UD_Iprefetcht1:
  case UD_Iprefetcht2: case UD_Ipush: case UD_Ipushfq: case UD_Irep:
  case UD_Irepne: case UD_Irsm: case UD_Isahf: case UD_Isetb: case UD_Isetbe:
  case UD_Isetl: case UD_Isetle: case UD_Iseto: case UD_Isetp: case UD_Isets:
  case UD_Isetz: case UD_Istmxcsr: case UD_Iverr: case UD_Iverw:
  case UD_Ivmclear: case UD_Ivmptrld: case UD_Ivmptrst: case UD_Ivmxon:
    DEBUG("Known readonly 1 op instruction");
    break;
    //potential write 1 operand instructions
  case UD_Idec: case UD_If2xm1: case UD_Ifabs: case UD_Ifchs: case UD_Ifcos:
  case UD_Ifnstcw: case UD_Ifnstenv: case UD_Ifnstsw: case UD_Ifptan:
  case UD_Ifrndint: case UD_Ifsin: case UD_Ifsincos: case UD_Ifsqrt:
  case UD_Iinc: case UD_Iinvlpg: case UD_Ineg: case UD_Inot:
    DEBUG("Known potential write 1 op instruction, testing op 0");
    test_operand(&ud_obj, 0, context);
    break;
    //readonly 2 operand instructions
  case UD_Ilea: case UD_Icmp:
    DEBUG("Known readonly 2 op instruction");
    break;
    //known potential writes with 2 operands
  case UD_Imov:
    DEBUG("Known potential write 2 op instruction, testing op 0");
    test_operand(&ud_obj, 0, context);
    break;
    //readonly 3 operand instructions
  case UD_Ipshufd:  case UD_Ipshufhw: case UD_Ipshuflw: case UD_Ipshufw:
    DEBUG("Known readonly 3 op instruction");
    break;
    //syscall calls
  case UD_Isyscall: case UD_Isysenter:
    DEBUG("Special case: syscall");
    log_syscall(context->uc_mcontext.gregs[REG_RAX], context);
    waiting_syscall = true;
    break;
  default:
    DEBUG("Unknown instruction, counting operands");
    ud_operand_t* op;
    int i = 0;
    do {
      if ((op = (ud_operand_t*) ud_insn_opr(&ud_obj, i)) != NULL) {
        if (i > 1) {
          cerr << "3-operand instructions not supported yet\n";
          exit(2);
        }
        i++;
      }
    } while (i < MAX_OPERANDS && op != NULL);

    if (i == 0) {
      DEBUG("0 operand instruction");
    }
    else {
      DEBUG("Instruction has " << i << " operands, testing op 0");
      test_operand(&ud_obj, 0, context);
    }
    break;
  }

  DEBUG("Continuing to single step");
  //set TRAP flag to continue single-stepping
  context->uc_mcontext.gregs[REG_EFL] |= 1 << 8;

  DEBUG("Finished trap handler");
}

void log_write(uint64_t dest_address) {
  DEBUG("Logging a write to " << int_to_hex(dest_address) << ", write/syscall count is now " << write_syscall_count + 1);
  if(write_syscall_count >= MAX_WRITE_SYSCALL_COUNT) {
    cerr << "Overflowing write/syscall flag array!\n";
    exit(2);
  }
  write_syscall_flag[write_syscall_count++] = true;

  DEBUG("Dereferencing destination address");
  uint64_t val = *((uint64_t*)dest_address);

  DEBUG("Write " << val << " to " << int_to_hex(dest_address));
        
  write_file.write((char*) &dest_address, sizeof(uint64_t));
  write_file.write((char*) &val, sizeof(uint64_t));

  DEBUG("Finished logging a write");
}

void log_syscall(uint64_t sys_num, ucontext_t* context) {
  DEBUG("Logging syscall (" << sys_num << "), write/syscall count is now " << write_syscall_count + 1);
  if(write_syscall_count >= MAX_WRITE_SYSCALL_COUNT) {
    cerr << "Overflowing write/syscall flag array!\n";
    exit(2);
  }
  write_syscall_flag[write_syscall_count++] = false;

  DEBUG("Looking up syscall");
  // look up syscall information in global syscalls array
  syscall_t syscall = syscalls[sys_num];
  int num_params = syscall.args;
  DEBUG("Syscall " << syscall.name << " has " << num_params << " parameters");

  DEBUG("Logging syscall number");
  sys_file.write((char*) &sys_num, sizeof(uint64_t));

  DEBUG("Logging syscall parameters");
  for (int i = 0; i < num_params; i++) {
    uint64_t reg_val = get_register(syscall_params[i], context);
    DEBUG("Logging syscall parameter " << i << ": " << reg_val);
    sys_file.write((char*) &reg_val, sizeof(uint64_t));
  }

  DEBUG("Finished logging syscall");
}

void log_sys_ret(uint64_t ret_value_reg) {
  DEBUG("Logging syscall return value: " << ret_value_reg);
  sys_file.write((char*) &ret_value_reg, sizeof(uint64_t));
  DEBUG("Finished logging syscall return value");
}

/**
 * Checks if the next instruction will only read or also write to memory
 * ud_t* obj: pointer to the object that disassembles the next instruction 
 * n: the position of the operand we inspect; destination is the last one 
 * context: context from the handler with general register information 
 * @returns bool: true if no writes to memory; false otherwise. 
 */
bool just_read(uint64_t mem_address, bool is_mem_opr, ucontext_t* context) {
  DEBUG("Determining if the instruction is readonly");
  if (is_mem_opr) {
    //if the instruction tries to access memory outside of the current
    //stack frame, we know it writes to memory

    // -128 = red zone
    uint64_t stack_ptr = context->uc_mcontext.gregs[REG_RSP] - 128;

    DEBUG("The stack frame is " << int_to_hex((uint64_t) stack_base) << " to " << int_to_hex(stack_ptr));

    DEBUG("Finished determining if instruction is readonly: " << ((uintptr_t) stack_base > mem_address && stack_ptr < mem_address));
    return ((uintptr_t) stack_base > mem_address && stack_ptr < mem_address); 
  }

  DEBUG("Finished determining if instruction is readonly: true (doesn't touch memory)");
  //if the instruction doesn't touch memory then it's fine
  return true;
}

/*
 * Translates from udis's register enum's to register addresses
 * obj: object containing the instruction to be disassembled
 * context: from the signal handler with general register information  
 */
uint64_t get_register(ud_type_t obj, ucontext_t* context) {
  DEBUG("Getting the register value from udis enum: " << obj);
  switch(obj) {
  case UD_R_RIP:
    return context->uc_mcontext.gregs[REG_RIP];
  case UD_R_RAX: case UD_R_EAX: case UD_R_AX: case UD_R_AL: case UD_R_AH:
    return context->uc_mcontext.gregs[REG_RAX];
  case UD_R_RCX: 
    return context->uc_mcontext.gregs[REG_RCX];
  case UD_R_RDX: case UD_R_EDX: case UD_R_DX: case UD_R_DL: case UD_R_DH:
    return context->uc_mcontext.gregs[REG_RDX];
  case UD_R_RBX:
    return context->uc_mcontext.gregs[REG_RBX];
  case UD_R_RSP:
    return context->uc_mcontext.gregs[REG_RSP];
  case UD_R_RBP:
    return context->uc_mcontext.gregs[REG_RBP];
  case UD_R_RSI:
    return context->uc_mcontext.gregs[REG_RSI];
  case UD_R_RDI:
    return context->uc_mcontext.gregs[REG_RDI];             
  case UD_R_R8:
    return context->uc_mcontext.gregs[REG_R8];
  case UD_R_R9:
    return context->uc_mcontext.gregs[REG_R9];              
  case UD_R_R10:
    return context->uc_mcontext.gregs[REG_R10];             
  case UD_R_R11:
    return context->uc_mcontext.gregs[REG_R11];
  case UD_R_R12:
    return context->uc_mcontext.gregs[REG_R12];
  case UD_R_R13:
    return context->uc_mcontext.gregs[REG_R13];
  case UD_R_R14:
    return context->uc_mcontext.gregs[REG_R14];
  case UD_R_R15:
    return context->uc_mcontext.gregs[REG_R15];
  case UD_NONE:
    return 0;
  default:
    DEBUG("Unsupported register!");
    return -1; 
  }
}

uint32_t* get_fp_register(ud_type_t obj, ucontext_t* context) {
  DEBUG("Getting the floating point register value from udis enum: " << obj);
  switch(obj) {
  case UD_R_XMM0:
    return context->uc_mcontext.fpregs->_xmm[0].element;
  case UD_R_XMM1:
    return context->uc_mcontext.fpregs->_xmm[1].element;
  case UD_R_XMM2:
    return context->uc_mcontext.fpregs->_xmm[2].element;
  case UD_R_XMM3:
    return context->uc_mcontext.fpregs->_xmm[3].element;
  case UD_R_XMM4:
    return context->uc_mcontext.fpregs->_xmm[4].element;
  case UD_R_XMM5:
    return context->uc_mcontext.fpregs->_xmm[5].element;
  case UD_R_XMM6:
    return context->uc_mcontext.fpregs->_xmm[6].element;
  case UD_R_XMM7:
    return context->uc_mcontext.fpregs->_xmm[7].element;
  case UD_R_XMM8:
    return context->uc_mcontext.fpregs->_xmm[8].element;
  case UD_R_XMM9:
    return context->uc_mcontext.fpregs->_xmm[9].element;
  case UD_R_XMM10:
    return context->uc_mcontext.fpregs->_xmm[10].element;
  case UD_R_XMM11:
    return context->uc_mcontext.fpregs->_xmm[11].element;
  case UD_R_XMM12:
    return context->uc_mcontext.fpregs->_xmm[12].element;
  case UD_R_XMM13:
    return context->uc_mcontext.fpregs->_xmm[13].element;
  case UD_R_XMM14:
    return context->uc_mcontext.fpregs->_xmm[14].element;
  case UD_R_XMM15:
    return context->uc_mcontext.fpregs->_xmm[15].element;    
  default:
    DEBUG("Unsupported register!");
    return NULL; 
  }
}

/**
 * A temporary gdb workaround debugger.
 */
void seg_handler(int sig, siginfo_t* info, void* context) {

  if (sig != SIGSEGV) {
    fprintf(stderr, "should not be here\n");
    exit(2); 
  }

  fprintf(stderr, "in SEG handler\n");
  fprintf(stderr, "SEGFAULT address: %p\n", info->si_addr);
  int j, nptrs; 
  void* buffer[200];
  char** strings;
  signal(sig, SIG_DFL);
  nptrs = backtrace(buffer, 200);

  backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO);
  printf("~~~\n");

  void* bt[1];
  bt[0] = (void*) ((ucontext_t*) context)->uc_mcontext.gregs[REG_RIP];

  backtrace_symbols_fd(bt, 1, STDOUT_FILENO);
}


#include "alpaca_shared.hh"

//citations: modified example code from
//https://github.com/aclements/libelfin/blob/master/examples/dump-syms.cc
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
#include <sys/types.h>
#include <sys/stat.h>

#include <ucontext.h>
#include <unistd.h>

// syscalls
#include <poll.h>
#include <sys/shm.h>
#include <sys/time.h>

#define MAX_OPERANDS 126
#define NUM_RET_REGS 4

#define MAX_WRITE_SYSCALL_COUNT 1024 * 1024 * 1024
#define MAX_WRITE_COUNT 100000000

using namespace std;

uint64_t mem_writing; //the destination address of an instruction that writes
bool large_write; // for 128-bit writes (xmm registers)
bool large_large_write; //for 256-bit writes(ymm registers AVX)
uint64_t* stack_base; //the beginning of the stack for the targeted function

//keep track of the detected writes and syscall of the function 
uint64_t write_syscall_count;
uint64_t write_count;

//true for write, false for syscall
bool write_syscall_flag[MAX_WRITE_SYSCALL_COUNT];

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
bool just_read(uint64_t mem_address, bool is_mem_opr, ucontext_t* context);
void log_write(uint64_t dest_address, bool large_write, bool large_large_write);
void test_operand(ud_t* obj, int n, int num_op, ucontext_t* context);
void trap_handler(int signal, siginfo_t* info, void* cont);
void log_syscall(uint64_t sys_num, ucontext_t* context);
void log_sys_ret(uint64_t ret_value_reg);


/**
 *Finds the destination memory address of an instruction
 */
uint64_t find_destination(const ud_operand_t* op, ucontext_t* context) {
  DEBUG("Finding the destination of instruction");
  int64_t offset; //displacement offset

  DEBUG("Size of offset: " << (int) op->offset << ", base register: " << op->base << ", index register: " << op->index);
  switch(op->offset) {
  case 8:
    DEBUG("Instruction offset is 8 bits long");
    offset = (int8_t) op->lval.sbyte;
    break; 
  case 16:
    DEBUG("Instruction offset is 16 bits long");
    offset = (int16_t) op->lval.sword;
    break;
  case 32:
    DEBUG("Instruction offset is 32 bits long");
    offset = (int32_t) op->lval.sdword;
    break;
  case 64:
    DEBUG("Instruction offset is 64 bits long");
    offset = (int64_t) op->lval.sqword;
    break;
  default:
    DEBUG("Irregular offset size (" << (int) op->offset << ")!");
    offset = 0;
  }

  uint8_t scale = 0;
  size_t base = get_register(op->base, context);
  if (op->index != UD_NONE) {
    if (op->scale == 0) {
      scale = 1;
      DEBUG("Scale hardcoded to 1");
    }
    else scale = op->scale;
  }
  size_t index = get_register(op->index, context);

  DEBUG("Offset: " << int_to_hex(offset) << ", base: " << int_to_hex(base) << ", index: " << index << ", scale: " << (int) scale);
  DEBUG("Finished finding destination: " << int_to_hex((uint64_t) (offset + base + (index * scale))));
  //calculating the memory address based on assembly register information 
  return (uint64_t) (offset + base + (index * scale)); 
}

void handle_push(ud_t* obj, ucontext_t* context) {
  /*
  const ud_operand_t* op = ud_insn_opr(obj, 0);      
  uint64_t reg_val = get_register(op->base, context);
  DEBUG("Handling a push, register value: " << int_to_hex(reg_val));
  mem_writing = context->uc_mcontext.gregs[REG_RSP]-8;
  DEBUG("Set mem_writing to " << int_to_hex(mem_writing) << ", rsp is " << int_to_hex(context->uc_mcontext.gregs[REG_RSP]));
  */
}

/**
 *Detects the operand type which can be a memory or a register
 *if it is not a read only instruction than records it as a memory write
 *if it is a register and a return register then mark it as touched 
 */

void test_operand(ud_t* obj, int n, int num_op, ucontext_t* context) {
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
      if(ud_insn_mnemonic(obj) == UD_Icmpxchg) DEBUG("cmpxchg value: " << int_to_hex(*(uint64_t*)mem_address));
      mem_writing = mem_address;

      const ud_operand_t* src_op = ud_insn_opr(obj, num_op-1);
      if (src_op->base == UD_R_XMM0 || src_op->base == UD_R_XMM1) {
        large_write = true;
      }
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
  writef((char*) &write_syscall_count, sizeof(uint64_t), return_file);

  DEBUG("Logging write/syscall flag");
  //flag to switch between memory writes and syscalls
  bitset<8> flag_byte;
  //updates 8 bits at a time and log the flag 
  for(int i = 0; i < (write_syscall_count / 8) + 1; i++) {
    flag_byte.reset(); 
    for(int j = 0; j < 8 && j + i * 8 < write_syscall_count; j++) {
      DEBUG("Write/syscall bool array value: " << write_syscall_flag[i*8 + j] << " at index " << (i*8 + j) << " (i is " << i << ")");
      if(write_syscall_flag[i * 8 + j]) {
        flag_byte.set(j, true);
      }
    }
   
    DEBUG("Write/syscall flag byte: " << flag_byte);
    writef((char*)&flag_byte, 1, return_file);
  }

  uint8_t reg_flag = 0; 
  //which registers we're writing to
  for (int i = 0; i < NUM_RET_REGS; i++) {
    if (ret_regs_touched[i]) reg_flag |= (1 << i);
  }

  DEBUG("Logging register flag: " << (int) reg_flag);
  writef((char*) &reg_flag, sizeof(uint8_t), return_file);

  DEBUG("Logging return registers");
  //logging the return registers
  for (int i = 0; i < NUM_RET_REGS; i++) {
    if (ret_regs_touched[i]) {
      if(i < 2) { //integer types
        uint64_t buf = get_register(ret_regs[i], context);
        DEBUG((i == 0 ? "RAX" : "RDX") << " register value: " << int_to_hex(buf));
        writef((char*) &buf, sizeof(uint64_t), return_file);
      } else { //floating point types
        float* buf = (float*)get_fp_register(ret_regs[i], context);
        DEBUG((i == 2 ? "XMM0" : "XMM1") << " register values: " << buf[0]
              << ", " << buf[1] << ", " << buf[2] << ", " << buf[3]);
        for (int j = 0; j < 4; j++)
          writef((char*) &buf[j], sizeof(float), return_file);
                                
      }
    }
  }

  DEBUG("Finished logging returns");
}

//ret addr logging
void log_ret_addrs(uint64_t addr) {
  DEBUG("Logging return address: " << int_to_hex(addr));
  writef((char*)&addr, sizeof(uint64_t), ret_addr_file);
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
  static unsigned int function_start_counter = 0;
  static uint64_t ret_addr = 0; //ret addr logging 
  
  uint64_t* rsp;

  ucontext_t* context = reinterpret_cast<ucontext_t*>(cont);

  debug_registers(context);

  
  //logging writes
  if (mem_writing != 0) {
    if (write_count > MAX_WRITE_COUNT) {
      cerr << "maximum write count reached!\n";
      exit(2);
    }
    
    DEBUG("Last instruction was a memory write to address: " << int_to_hex(mem_writing) << " (count: " << write_count << ")");
    DEBUG("RAX is: " << int_to_hex(context->uc_mcontext.gregs[REG_RAX]));
    write_count++;
    log_write(mem_writing, large_write, large_large_write);
    mem_writing = 0;
    large_write = false;
    large_large_write = false;
  }
  
  //if the last instruction was a syscall then grab and log the return value
  if(waiting_syscall) {
    DEBUG("Last instruction was a syscall, gathering return value");
    log_sys_ret(context->uc_mcontext.gregs[REG_RAX]);
    waiting_syscall = false;
  }

  if (start_byte == 0x55) {
    if (first_run) {
      DEBUG_CRITICAL("Target function called (" << function_start_counter++ << ")");
      
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
      DEBUG_CRITICAL("Target function called (" << function_start_counter++ << ")");
      
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
      DEBUG_CRITICAL("The target function has returned");
      
      log_returns(context);
      log_ret_addrs(ret_addr); //ret addr logging
      
      DEBUG("Stopping single stepping");
      //stops single-stepping
      context->uc_mcontext.gregs[REG_EFL] &= ~(1LL << 8);

      DEBUG("Enabling single step once the target function is called again");
      start_byte = single_step(func_address);

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

  DEBUG("Instruction at " << int_to_hex(context->uc_mcontext.gregs[REG_RIP]) << ": " << ud_insn_asm(&ud_obj) << " (" << ud_insn_hex(&ud_obj) << ")");
  for(int i = 0; i < 8; i++) {
    DEBUG("Instruction byte at " << i << ": " << int_to_hex((uint64_t)ud_insn_ptr(&ud_obj)[i]));
  }
  //SPECIAL TEST CASE
  if(context->uc_mcontext.gregs[REG_RIP] == 0x7fff7bd1de00) check_self_maps();

  /*
    void* buf[200];
    int bt = backtrace(buf, 200);
    DEBUG("Getting the backtrace (" << bt << ")");
    backtrace_symbols_fd(buf, bt, 2);
  */

  uint8_t instr[18];
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
  case UD_Iprefetcht2: case UD_Irep:
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
    test_operand(&ud_obj, 0, 1, context);
    break;
    //readonly 2 operand instructions
  case UD_Ilea: case UD_Icmp: case UD_Itest:
    DEBUG("Known readonly 2 op instruction");
    break;
    //known potential writes with 2 operands
  case UD_Imov:
    DEBUG("Known potential write 2 op instruction, testing op 0");
    memcpy(instr, ud_insn_ptr(&ud_obj), 18);
    if(instr[0] == 0x88 && instr[1] == 0x0f) {
      DEBUG("Special case: 88 0f");
      mem_writing = context->uc_mcontext.gregs[REG_RDI];
    } else {
      test_operand(&ud_obj, 0, 2, context);
    }
    break;
    //readonly 3 operand instructions
  case UD_Ipshufd:  case UD_Ipshufhw: case UD_Ipshuflw: case UD_Ipshufw: case UD_Ishufps:
    DEBUG("Known readonly 3 op instruction");
    break;
    //syscall calls
  case UD_Isyscall: case UD_Isysenter:
    DEBUG("Special case: syscall");
    log_syscall(context->uc_mcontext.gregs[REG_RAX], context);
    waiting_syscall = true;
    break;
    //special case for push 
  case UD_Ipush:
    DEBUG("Special case: push");
    handle_push(&ud_obj, context);
    break;
  case UD_Ipushfq:
    DEBUG("Special case: pushfq not supported yet\n");
    exit(2);
  case UD_Iinvalid:
    DEBUG("Invalid instruction: udis cannot recognize it");
    memcpy(instr, ud_insn_ptr(&ud_obj), 18);
    if((instr[0] == 0xc5 || instr[0]== 0xc4) && (instr[1] == 0xfd || instr[1] == 0xf9 || instr[1] == 0xfa || instr[1] == 0xfe)) {
      if ((instr[0] == 0xc4)  && (instr[2] == 0x6f || instr[2] == 0x7f)) {
        DEBUG("Special case: 3 byte prefix vmovdqa");
        DEBUG("Changing opcode bytes to act as instruction");

        if (instr[2] & 0b100) {
          DEBUG("YMM registers used");
          large_large_write = true;
        } else {
          DEBUG("XMM registers used");
          large_write = true;
        }

        //shift one byte b/c mov has a 2 byte prefix
        for (int i = 1; i < 9; i++) {
          instr[i-1] = instr[i];
        }
      } else {
        DEBUG("Special case: 2 byte prefix vmovdqa");
        DEBUG("Changing opcode bytes to act as instruction");

        if (instr[1] & 0b100) {
          DEBUG("YMM registers used");
          large_large_write = true;
        } else {
          DEBUG("XMM registers used");
          large_write = true;
        }
      }

      instr[0] = (instr[1] == 0xfd || instr[1] == 0xf9) ? 0x66 : 0xf3; //movdqa 0xfd vs. movdqu 0xfe
      instr[1] = 0x0f;
      //movdqa specific with same operand ordering as vmovdqa based on 0x7f or 0x6f third byte encoding
      for (int i = 0; i < 8; i++) {
        DEBUG("Instruction byte from instr[ " << i << "] : " << int_to_hex((uint64_t)instr[i]));
      }
      ud_set_input_buffer(&ud_obj, &instr[0], 17);
      ud_disassemble(&ud_obj);
      
      DEBUG("Updated instruction: " << ud_insn_asm(&ud_obj) << " (" << ud_insn_hex(&ud_obj) << ")");
      for(int i = 0; i < 8; i++) {
        DEBUG("Instruction byte at " << i << ": " << int_to_hex((uint64_t)ud_insn_ptr(&ud_obj)[i]));
      }
      test_operand(&ud_obj, 0, 2, context);
    } else if (instr[0] == 0xc5 && instr[1] == 0xf8 && instr[2] == 0x77){
      DEBUG("Special case: vzeroupper (only affects registers)");
    } else {
      DEBUG("Unknown invalid instruction");
      exit(2);
    }
            
    break;
  default:
    DEBUG("Unknown instruction, counting operands");
    ud_operand_t* op;
    int i = 0;
    do {
      if ((op = (ud_operand_t*) ud_insn_opr(&ud_obj, i)) != NULL) {
        if (i > 1) {
          cerr << "3-operand instruction: " << ud_insn_asm(&ud_obj) << "\n";
        }
        i++;
      }
    } while (i < MAX_OPERANDS && op != NULL);

    if (i == 0) {
      DEBUG("0 operand instruction");
    }
    else {
      DEBUG("Instruction has " << i << " operands, testing op 0");
      test_operand(&ud_obj, 0, i, context);
    }
    break;
  }

  DEBUG("Continuing to single step");
  //set TRAP flag to continue single-stepping
  context->uc_mcontext.gregs[REG_EFL] |= 1 << 8;

  DEBUG("Finished trap handler");
}

void log_write(uint64_t dest_address, bool large_write, bool large_large_write) {
  DEBUG("Logging a write to " << int_to_hex(dest_address) << ", write/syscall count is now " << write_syscall_count + 1);
  if(write_syscall_count >= MAX_WRITE_SYSCALL_COUNT) {
    cerr << "Overflowing write/syscall flag array!\n";
    exit(2);
  }
  write_syscall_flag[write_syscall_count++] = true;

  if(large_write) { DEBUG("This is a large write"); }
  if(large_large_write) { DEBUG("This is a large large write"); }

  DEBUG("Dereferencing destination address");
  uint64_t val = ((uint64_t*)dest_address)[0];

  DEBUG("Write " << int_to_hex(val) << " to " << int_to_hex(dest_address));
        
  writef((char*) &dest_address, sizeof(uint64_t), write_file);
  DEBUG("Dest addr is " << int_to_hex(dest_address));
  writef((char*) &val, sizeof(uint64_t), write_file);

  if(large_large_write) {
    DEBUG("Logging second part of large large write");
    log_write(dest_address + 8, false, false);
    DEBUG("Logging third part of large large write");
    log_write(dest_address + 16, false, false);
    DEBUG("Logging fourth part of large large write");
    log_write(dest_address + 24, false, false);
  } else if(large_write) {
    DEBUG("Logging second part of large write");
    log_write(dest_address + 8, false, false);
  }

  DEBUG("Finished logging a write");
}

void log_local_syscall(uint64_t buf_addr, uint64_t buf_size, uint64_t syscall_count, uint64_t stack_ptr) {
  DEBUG("Logging local syscall");

  if ((uintptr_t) stack_base > buf_addr && stack_ptr < buf_addr) {
    DEBUG("Syscall uses a local buffer");
  
    DEBUG("Buffer address is " << int_to_hex(buf_addr) << "; buffer size is " << buf_size);

    DEBUG("Logging the write/syscall count number");
    writef((char*) &syscall_count, sizeof(uint64_t), local_sys_file);
    
    if(buf_addr == 0) {
      DEBUG("Buffer address is NULL, setting the size to 0 and skipping buffer contents");
      char zero = 0;
      writef(&zero, sizeof(char), local_sys_file);
    } else {
      DEBUG("Logging the buffer size");
      writef((char*) &buf_size, sizeof(uint64_t), local_sys_file);

      DEBUG("Logging the buffer contents");
      writef((char*) buf_addr, buf_size, local_sys_file);
    }
  } else {
    DEBUG("Syscall does not use a local buffer");
  }

  DEBUG("Finished logging local syscall");
}

// not beautifully named but easier on the eyes
#define local_sizereg(buf_reg, size_reg) log_local_syscall(get_register(syscall_params[(buf_reg)], context), \
                                                           get_register(syscall_params[(size_reg)], context), \
                                                           syscall_count, \
                                                           stack_ptr)
#define local_sizeregptr(buf_reg, size_reg) log_local_syscall(get_register(syscall_params[(buf_reg)], context), \
                                                              *(uint64_t*)get_register(syscall_params[(size_reg)], context), \
                                                              syscall_count, \
                                                              stack_ptr)
#define local_sizeconst(buf_reg, size) log_local_syscall(get_register(syscall_params[(buf_reg)], context), \
                                                         (size),        \
                                                         syscall_count, \
                                                         stack_ptr)
#define local_sizemultreg(buf_reg, coeff, size_reg) log_local_syscall(get_register(syscall_params[(buf_reg)], context), \
                                                                      (coeff) * get_register(syscall_params[(size_reg)], context), \
                                                                      syscall_count, \
                                                                      stack_ptr)
#define SUPPORTED_SYSCALLS 55 // number of the highest supported syscall

void check_local_syscall(uint64_t sys_num, uint64_t syscall_count, ucontext_t* context) {
  DEBUG("Checking if syscall uses a local buffer");

  uint64_t stack_ptr = context->uc_mcontext.gregs[REG_RSP] - 128;
  ud_type_t buf_reg, size_reg;
  uint64_t buf_size = -1;

  switch(sys_num) {
  case 0: case 1: case 17: case 18: // read, write, pread64, pwrite64
    local_sizereg(1, 2);
    break;
  case 2: case 21: // open and access
    local_sizeconst(0, FILENAME_MAX);
    break;
  case 4: case 6: // stat and lstat
    local_sizeconst(0, FILENAME_MAX);
    local_sizeconst(1, sizeof(struct stat));
    break;
  case 5: // fstat
    local_sizeconst(1, sizeof(struct stat));
    break;
  case 7: // poll
    local_sizeconst(0, sizeof(struct pollfd));
    break;
  case 13: // rt_sigaction
    local_sizeconst(1, sizeof(struct sigaction));
    local_sizeconst(2, sizeof(struct sigaction));
    break;
  case 14: // rt_sigprocmask
    local_sizeconst(1, sizeof(sigset_t));
    local_sizeconst(2, sizeof(sigset_t));
    break;
  case 19: case 20: // readv and writev
    local_sizemultreg(1, sizeof(struct iovec), 2);
    break;
  case 22: // pipe
    local_sizeconst(0, sizeof(int) * 2);
    break;
  case 23: // select
    local_sizemultreg(1, sizeof(fd_set), 0);
    local_sizemultreg(2, sizeof(fd_set), 0);
    local_sizemultreg(3, sizeof(fd_set), 0);
    local_sizeconst(4, sizeof(struct timespec));
    break;
  case 27: // mincore
    local_sizereg(2, 1);
    break;
  case 30: // shmat
    struct shmid_ds shmbuf;
    shmctl(get_register(syscall_params[0], context), IPC_STAT, &shmbuf);
    local_sizeconst(1, shmbuf.shm_segsz);
    break;
  case 31: // shmctl
    local_sizeconst(2, sizeof(struct shmid_ds));
    break;
  case 35: // nanosleep
    local_sizeconst(0, sizeof(struct timespec));
    local_sizeconst(1, sizeof(struct timespec));
    break;
  case 36: // getitimer
    local_sizeconst(1, sizeof(struct itimerval));
    break;
  case 38: // setitimer
    local_sizeconst(1, sizeof(struct itimerval));
    local_sizeconst(2, sizeof(struct itimerval));
    break;
  case 40: // sendfile
    local_sizeconst(2, sizeof(off_t));
    break;
  case 42: case 49: // connect and bind
    local_sizereg(1, 2);
    break;
  case 43: case 51: case 52: // accept, getsockname, and getpeername
    local_sizeregptr(1, 2);
    local_sizeconst(2, sizeof(int));
    break;
  case 44: // sendto
    local_sizereg(1, 2);
    local_sizereg(4, 5);
    break;
  case 45: // recvfrom
    local_sizereg(1, 2);
    local_sizeregptr(4, 5);
    local_sizeconst(5, sizeof(int));
    break;
  case 46: case 47: // sendmsg and recvmsg
    local_sizeconst(1, sizeof(struct msghdr));
    break;
  case 53: // socketpair
    local_sizeconst(3, sizeof(int) * 2);
    break;
  case 54: // setsockopt
    local_sizereg(3, 4);
    break;
  case 55: // getsockopt
    local_sizeregptr(3, 4);
    break;
  default:
    if(sys_num > SUPPORTED_SYSCALLS) {
      cerr << "Unsupported syscall encountered: " << sys_num << "!\n";
      exit(3);
    }
    DEBUG("Syscall does not use any buffers");
    return;
  }

  DEBUG("Finished checking if syscall uses a local buffer");
}

void log_syscall(uint64_t sys_num, ucontext_t* context) {
  static uint64_t syscall_count = 0;
  
  DEBUG("Logging a syscall (" << sys_num << "), write/syscall count is now " << write_syscall_count + 1 << ", syscall count is now " << syscall_count);
  if(write_syscall_count >= MAX_WRITE_SYSCALL_COUNT) {
    cerr << "Overflowing write/syscall flag array!\n";
    exit(2);
  }

  write_syscall_flag[write_syscall_count++] = false;
  
  DEBUG("Logging the syscall address");
  writef((char*) &context->uc_mcontext.gregs[REG_RIP], sizeof(uint64_t), ret_addr_file);
  
  DEBUG("Looking up syscall");
  // look up syscall information in global syscalls array
  syscall_t syscall = syscalls[sys_num];
  int num_params = syscall.args;
  DEBUG("Syscall " << syscall.name << " has " << num_params << " parameters");

  DEBUG("Logging syscall number");
  writef((char*) &sys_num, sizeof(uint64_t), sys_file);

  DEBUG("Logging syscall parameters");
  for (int i = 0; i < num_params; i++) {
    uint64_t reg_val = get_register(syscall_params[i], context);
    DEBUG("Logging syscall parameter " << i << ": " << reg_val);
    writef((char*) &reg_val, sizeof(uint64_t), sys_file);
  }
  
  check_local_syscall(sys_num, syscall_count, context);

  syscall_count++;

  DEBUG("Finished logging syscall");
}

void log_sys_ret(uint64_t ret_value_reg) {
  DEBUG("Logging syscall return value: " << ret_value_reg);
  writef((char*) &ret_value_reg, sizeof(uint64_t), sys_file);
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

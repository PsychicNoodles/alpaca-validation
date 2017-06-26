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

#define MAX_WRITE_SYSCALL_COUNT 1024

using namespace std;

uint64_t mem_writing; 
uint64_t* stack_base;

uint64_t write_syscall_count;
bool write_syscall_flag[1024]; //true for write, false for syscall

uint8_t func_start_byte; //the byte overwrtitten with 0xCC for single-stepping

ud_type_t ret_regs[NUM_RET_REGS] = {UD_R_RAX, UD_R_RDX, UD_R_XMM0, UD_R_XMM1};
ud_type_t rax_regs[5] = {UD_R_RAX, UD_R_EAX, UD_R_AX, UD_R_AH, UD_R_AL};
ud_type_t rdx_regs[5] = {UD_R_RDX, UD_R_EDX, UD_R_DX, UD_R_DH, UD_R_DL};
bool ret_regs_touched[NUM_RET_REGS] = {false};

ud_type_t syscall_params[6] = {UD_R_RDI, UD_R_RSI, UD_R_RDX, UD_R_R10, UD_R_R8, UD_R_R9};

//function declarations
uint64_t get_register(ud_type_t obj, ucontext_t* context);
uint32_t* get_fp_register(ud_type_t obj, ucontext_t* context);
void initialize_ud_obj(ud_t* ud_obj);
bool just_read(uint64_t mem_address, bool is_mem_opr, ucontext_t* context);
void log_writes(uint64_t dest_address);
void test_operand(ud_t* obj, int n);
void trap_handler(int signal, siginfo_t* info, void* cont);
void log_syscall(uint64_t sys_num, ucontext_t* context);
void log_sys_ret(uint64_t ret_value_reg);

/**
 * Enables single-stepping (instruction by instruction) through the function
 * func_address: (virtual) address of the function in memory
 */
void single_step(uint64_t func_address) {
  //        write_count = 0; //setup
  uint64_t page_start = func_address & ~(PAGE_SIZE-1) ;

  //making the page writable, readable and executable
  if (mprotect((void*) page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
    fprintf(stderr, "%s\n", strerror(errno));
    exit(2); 
  }

  //setting the last byte to 0xCC causes a SIGTRAP signal for single-stepping
  func_start_byte = ((uint8_t*)func_address)[0];
  ((uint8_t*)func_address)[0] = 0xCC;

  //switch back to old permissions
}

uint64_t find_destination(const ud_operand_t* instrct, ucontext_t* context) {
  int64_t offset; //displacement offset

  switch(instrct->offset) {
  case 8:
    offset = (int8_t) instrct->lval.sbyte;
    break; 
  case 16:
    offset = (int16_t) instrct->lval.sword;
    break;
  case 32:
    offset = (int32_t) instrct->lval.sdword;
    break;
  case 64:
    offset = (int64_t) instrct->lval.sqword;
    break;
  default:
    offset = 0;
  }

  fprintf(stderr, "offset: %lu, base: %lu, index: %lu, scale: %u\n", offset, get_register(instrct->base, context), get_register(instrct->index, context), instrct->scale);
  //calculating the memory address based on assembly register information 
  return (uint64_t) (offset +
                     get_register(instrct->base, context) +
                     (get_register(instrct->index, context)*
                      instrct->scale)); 
}

void test_operand(ud_t* obj, int n, ucontext_t* context) {
  fprintf(stderr, "test_operand with n=%d\n", n);
        
  const ud_operand_t* instrct = ud_insn_opr(obj, n);
        
  bool is_mem_opr = instrct->type == UD_OP_MEM;
  bool is_reg_opr = instrct->type == UD_OP_REG;
        
  fprintf(stderr, "is_mem_opr: %s\n", is_mem_opr ? "true" : "false");
  fprintf(stderr, "is_reg_opr: %s\n", is_reg_opr ? "true" : "false");
  fprintf(stderr, "base of opr %d: %d\n", n, instrct->base);

  if (is_mem_opr) {
    uint64_t mem_address = find_destination(instrct, context);
    fprintf(stderr, "memory address after find destination: %p\n", (void*)mem_address);
                
    if (just_read(mem_address, is_mem_opr, context)) fprintf(stderr, "read in operand %d\n", n);
    else mem_writing = mem_address;
    if (instrct->base == UD_R_RIP) mem_writing += ud_insn_len(obj);
  } else if (is_reg_opr) {

    for (int i = 0; i < NUM_RET_REGS; i ++) {
      if (i == 0) {
        for (int j = 0; j < 5; j++) {
          if (instrct->base == rax_regs[j]) {
            ret_regs_touched[i] = true;
          }
        }
      } else if (i == 1) {
        for (int j = 0; j < 5; j++) {
          if (instrct->base == rdx_regs[j]) {
            ret_regs_touched[i] = true;
          }
        }
      } else {
        if (instrct->base == ret_regs[i]) {
          ret_regs_touched[i] = true;
        }
      }
    }
  }
}

void initialize_ud(ud_t* ud_obj) {
  ud_init(ud_obj);
  ud_set_mode(ud_obj, 64);
  ud_set_syntax(ud_obj, UD_SYN_ATT);
  ud_set_vendor(ud_obj, UD_VENDOR_INTEL);
}

void log_returns(ucontext_t* context) {
  fprintf(stderr, "writing write/syscall count %lu\n", write_syscall_count);
  return_file.write((char*) &write_syscall_count, sizeof(uint64_t));

  if(write_syscall_count > 0) {
    fprintf(stderr, "write/syscall flag should be ");
    for(int i = 0; i < write_syscall_count; i++) {
      fprintf(stderr, "%d", write_syscall_flag[i] == true ? 1 : 0);
    }
    fprintf(stderr, "\n");
  }

  bitset<8> flag_byte;
  for(int i = 0; i < (write_syscall_count / 8) + 1; i++) {
    flag_byte.reset(); 
    for(int j = 0; j < 8 && j + i * 8 < write_syscall_count; j++) {
      if(write_syscall_flag[i * 8 + j]) {
        flag_byte.set(j, true);
      }
    }
    fprintf(stderr, "writing write/syscall flag byte %s\n", flag_byte.to_string().c_str());
    return_file.write((char*)&flag_byte, 1);
  }
        
  uint8_t reg_flag = 0; 
  //which/how many registers we're writing to
  for (int i = 0; i < NUM_RET_REGS; i++) {
    if (ret_regs_touched[i]) reg_flag |= (1 << i);
  }

  fprintf(stderr, "writing reg_flag: %d\n", reg_flag);
  return_file.write((char*) &reg_flag, 1);

  for (int i = 0; i < 4; i++) {
    if (ret_regs_touched[i]) {
      if(i < 2) { //integer types
        uint64_t buf = get_register(ret_regs[i], context);
        return_file.write((char*) &buf, 8);
        fprintf(stderr, "value of %d register is: %lu\n", i, buf);
      } else { //floating point types
        fprintf(stderr, "fp type (%d)\n", i);
        float* buf = (float*)get_fp_register(ret_regs[i], context);

        for (int j = 0; j < 4; j++)
          return_file.write((char*) &buf[j], sizeof(float));
                                
      }
    }
  } 
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

  fprintf(stderr, "in trap handler\n");
  if (signal != SIGTRAP) {
    fprintf(stderr, "Signal received not SIGTRAP\n");
    exit(2);
  }

  //used to keep track of the stack manipulation 
  static int run = 0;
  static bool return_reached = false;
  static int call_count = 0;
  static ud_t ud_obj;
  static bool non_regular_start = false;
  static bool waiting_syscall = false;


  //logging writes
  fprintf(stderr, "mem_writing = %p (cc %d)\n", (void*)mem_writing, call_count);
  if (mem_writing != 0) {
    log_writes(mem_writing);
    mem_writing = 0;
  }
  
  ucontext_t* context = reinterpret_cast<ucontext_t*>(cont);

  if(waiting_syscall) {
          log_sys_ret(context->uc_mcontext.gregs[REG_RAX]);
          fprintf(stderr, "rax logged %lld",context->uc_mcontext.gregs[REG_RAX]);
          waiting_syscall = false;
  }

  if (func_start_byte == 0x55) {
    fprintf(stderr, "func_start_byte is 0x55\n");
    if (!run) {
      //Faking the %rbp stack push to account for the 0xCC byte overwrite
      stack_base = (uint64_t*)context->uc_mcontext.gregs[REG_RSP];
      uint64_t frame = (uint64_t)context->uc_mcontext.gregs[REG_RBP];

      fprintf(stderr, "stack_base: %p, rdi: %p\n", (void*)stack_base, (void*)context->uc_mcontext.gregs[REG_RDI]);

      //needs further explanation 
      stack_base--;
      *stack_base = frame;
      context->uc_mcontext.gregs[REG_RSP] = (uint64_t)stack_base;

      initialize_ud(&ud_obj);

      run = 1;
      ((uint8_t*)func_address)[0] = func_start_byte;
    }
                
  }  else {

    non_regular_start = true;
    run = 1; 
    fprintf(stderr, "func_start_byte was not 0x55, is %hhu\n",func_start_byte);
    ((uint8_t*)func_address)[0] = func_start_byte; //putting the original byte back
                    
    initialize_ud(&ud_obj);
  }

  //grabs next instruction to disassemble 
  ud_set_input_buffer(&ud_obj, (uint8_t*) context->uc_mcontext.gregs[REG_RIP], 18);
  ud_disassemble(&ud_obj);

  //if end of a function is reached in the next step  
  if (return_reached) {
    call_count--;
    return_reached = false;
              
    if(call_count < 0) {
      fprintf(stderr, "returned from target function\n");
                                
      //keep track of writing number
      fprintf(stderr, "write_syscall_count: %lu\n", write_syscall_count);

      log_returns(context);
                        
      if (!non_regular_start) {
        //stops single-stepping
        context->uc_mcontext.gregs[REG_EFL] &= ~(1LL << 8);
      }

      single_step(func_address);
  
      non_regular_start = false; 
      run = 0;
      call_count = 0;
      write_syscall_count = 0;

      memset(ret_regs_touched, false, NUM_RET_REGS*sizeof(bool)); 

      return;
    }
  }

  fprintf(stderr, "assembly instruction: %s\n", ud_insn_asm(&ud_obj));

  switch (ud_insn_mnemonic(&ud_obj)) {
  case UD_Iret: case UD_Iretf:
    fprintf(stderr, "special case: ret (call_count: %d)\n", call_count);
    return_reached = true;
    break;

  case UD_Icall:
    fprintf(stderr, "special case: call\n");
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
    fprintf(stderr, "known readonly 1 op instruction\n");
    break;
    //potential write 1 operand instructions
  case UD_Idec: case UD_If2xm1: case UD_Ifabs: case UD_Ifchs: case UD_Ifcos:
  case UD_Ifnstcw: case UD_Ifnstenv: case UD_Ifnstsw: case UD_Ifptan:
  case UD_Ifrndint: case UD_Ifsin: case UD_Ifsincos: case UD_Ifsqrt:
  case UD_Iinc: case UD_Iinvlpg: case UD_Ineg: case UD_Inot:
    fprintf(stderr, "known potential write 1 op instruction\n");
    test_operand(&ud_obj, 0, context);
    break;
    //readonly 2 operand instructions
  case UD_Ilea: case UD_Icmp:
    break;
    //known potential writes with 2 operands
  case UD_Imov:
    fprintf(stderr, "known potential write 2 op instruction\n");
    test_operand(&ud_obj, 0, context);
    break;
    //readonly 3 operand instructions
  case UD_Ipshufd:  case UD_Ipshufhw: case UD_Ipshuflw: case UD_Ipshufw:
    break;
    //syscall calls
  case UD_Isyscall: case UD_Isysenter: 
    log_syscall(context->uc_mcontext.gregs[REG_RAX], context);
    waiting_syscall = true;
    break;
  default:
    fprintf(stderr, "unknown operation, testing all operands\n");
    ud_operand_t* op;
    int i = 0;
    do {
      if ((op = (ud_operand_t*) ud_insn_opr(&ud_obj, i)) != NULL) {
        if (i > 1) {
          fprintf(stderr, "3-operand instructions not supported yet\n");
          exit(2);
        }
        i++;
      }
    } while (i < MAX_OPERANDS && op != NULL);

    if (i == 0) fprintf(stderr, "0 operand instruction\n"); //not a write
    else test_operand(&ud_obj, 0, context); 
    break;
  }

  if (non_regular_start) {
    non_regular_start = false; 
    single_step(context->uc_mcontext.gregs[REG_RIP]); 
  } else {
    //set TRAP flag to continue single-stepping
    context->uc_mcontext.gregs[REG_EFL] |= 1 << 8;
  }
   
}

//what happens to 3-operand instructions? 
void log_writes(uint64_t dest_address) {
  fprintf(stderr, "entered log writes\n");
  write_syscall_flag[write_syscall_count++] = true;
  fprintf(stderr, "pushed write syscall flag bit, current count: %lu\n", write_syscall_count);

  uint64_t val = *((uint64_t*)dest_address);
        
  fprintf(stderr, "writing to %lu address: %p\n",val, (void*) dest_address);
        
  write_file.write((char*) &dest_address, sizeof(uint64_t));
  write_file.write((char*) &val, sizeof(uint64_t));
  fprintf(stderr, "writing successful\n");
}

//logging syscalls: uint64_t syscall num, uint64_t[] syscall params, syscall return check
// log num of syscalls for pre and post in the return file 
void log_syscall(uint64_t sys_num, ucontext_t* context) {
  fprintf(stderr, "logging syscall %lu\n", sys_num);
  write_syscall_flag[write_syscall_count++] = false;
  syscall_t syscall = syscalls[sys_num];
  string syscall_name = syscall.name;
  int num_params = syscall.args;

  sys_file.write((char*) &sys_num, sizeof(uint64_t));
    
  for (int i = 0; i < num_params; i++) {
    uint64_t reg_val = get_register(syscall_params[i], context);
    fprintf(stderr, "syscall param %d is %lu\n", i, reg_val);
    sys_file.write((char*) &reg_val, sizeof(uint64_t));
  }
 
}

void log_sys_ret(uint64_t ret_value_reg) {
  fprintf(stderr, "syscall return value is %lu\n", ret_value_reg);
  sys_file.write((char*) &ret_value_reg, sizeof(uint64_t));
}

/**
 * Checks if the next instruction will only read or also write to memory
 * ud_t* obj: pointer to the object that disassembles the next instruction 
 * n: the position of the operand we inspect; destination is the last one 
 * context: context from the handler with general register information 
 * @returns bool: true if no writes to memory; false otherwise. 
 */
bool just_read(uint64_t mem_address, bool is_mem_opr, ucontext_t* context) {
  if (is_mem_opr) {
    //if the instruction tries to access memory outside of the current
    //stack frame, we know it writes to memory

    // -128 = red zone
    uint64_t stack_ptr = context->uc_mcontext.gregs[REG_RSP] - 128;
                
    fprintf(stderr, "stack frame rsp is %p to %p\n", (void*) stack_base, (void*) stack_ptr);
                
    return ((uintptr_t) stack_base > mem_address && stack_ptr < mem_address); 
  }

  //if the instruction doesn't touch memory then it's fine
  return true;
}

//expand the list!
/*
 * Translates from udis's register enum's to register addresses
 * obj: object containing the instruction to be disassembled
 * context: from the signal handler with general register information  
 */
uint64_t get_register(ud_type_t obj, ucontext_t* context) {
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
    fprintf(stderr, "unsupported register\n");
    return -1; 
  }
}

uint32_t* get_fp_register(ud_type_t obj, ucontext_t* context) {
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
    fprintf(stderr, "unsupported register\n");
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


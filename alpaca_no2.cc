#define _GNU_SOURCE

#include "alpaca_shared.hh"

//citations: modified example code from
//https://github.com/aclements/libelfin/blob/master/examples/dump-syms.cc
#include "elf++.hh" //parsing the binary file 
#include "x86jump.h" //jumping to function disabler
#include <udis86.h> //interpreting assembly instructions

#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <execinfo.h>
#include <fstream>
#include <inttypes.h>
#include <link.h>
#include <new>

#include <queue>
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
#define NUM_RET_REGS 12

using namespace std;

uint64_t mem_writing; 
uint64_t write_count;
uint64_t* stack_base; 
fstream return_file; //for logging later
fstream write_file; //for logging later
uint64_t func_address; //the address of the target function
uint8_t func_start_byte; //the byte overwrtitten with 0xCC for single-stepping
queue<uint64_t> rets; //return values for the disabler function

ud_type_t ret_regs[NUM_RET_REGS] = {UD_R_RAX, UD_R_RDX, UD_R_EAX, UD_R_EDX, UD_R_AX, UD_R_DX, UD_R_AH, UD_R_AL, UD_R_DH, UD_R_DL, UD_R_XMM0, UD_R_XMM1};
bool ret_regs_touched[NUM_RET_REGS] = {false}; 

typedef int (*main_fn_t)(int, char**, char**);
main_fn_t og_main;

//function declarations
uint64_t get_register(ud_type_t obj, ucontext_t* context);
uint32_t* get_fp_register(ud_type_t obj, ucontext_t* context);
void initialize_ud_obj(ud_t* ud_obj);
bool just_read(uint64_t mem_address, bool is_mem_opr, ucontext_t* context);
void mimic_writes(uint64_t dest_address);
void test_operand(ud_t* obj, int n);
void trap_handler(int signal, siginfo_t* info, void* cont);


/**
 * Enables single-stepping (instruction by instruction) through the function
 * func_address: (virtual) address of the function in memory
 */
void single_step(uint64_t func_address) {
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
                else mem_writing = mem_address + ud_insn_len(obj);
        } else if (is_reg_opr) {

                for (int i = 0; i < NUM_RET_REGS; i ++) {
                        if (instrct->base == ret_regs[i]) ret_regs_touched[i] = true; 
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

        uint64_t wc = write_count; 
        return_file.write((char*) &wc, 8);

        uint16_t flag = 0; 
        //which/how many registers we're writing to
        for (int i = 0; i < NUM_RET_REGS; i++) {
                if (ret_regs_touched[i]) flag |= (1 << i);
        }

        fprintf(stderr, "writing flag: %d\n", flag);
        return_file.write((char*) &flag, 1);

        for (int i = 0; i < NUM_RET_REGS; i++) {
                if (ret_regs_touched[i]) {
                        if(i < 10) { //integer types
                                uint64_t buf = get_register(ret_regs[i], context);
                                return_file.write((char*) &buf, 8);
                        } else { //floating point types
                                uint32_t* buf = get_fp_register(ret_regs[i], context);
                                for(int j = 0; j < 4; j++) return_file.write((char*) &buf[j], 4);
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

        //logging writes
        fprintf(stderr, "mem_writing = %p\n", (void*)mem_writing);
        if (mem_writing != 0) {
                mimic_writes(mem_writing);
                mem_writing = 0;
        }

        //used to keep track of the stack manipulation 
        static int run = 0;
        static bool return_reached = false;
        static int call_count = 0;
        static ud_t ud_obj;
        static bool non_regular_start = false; 

        ucontext_t* context = reinterpret_cast<ucontext_t*>(cont);

        if (func_start_byte == 0x55) {
                fprintf(stderr, "func_start_byte is 0x55\n");
                if (!run) {
                        //Faking the %rbp stack push to account for the 0xCC byte overwrite
                        stack_base = (uint64_t*)context->uc_mcontext.gregs[REG_RSP];
                        uint64_t frame = (uint64_t)context->uc_mcontext.gregs[REG_RBP];

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
                        fprintf(stderr, "write_count: %lu\n", write_count);

                        log_returns(context);
                        
                        if (!non_regular_start) {
                                //stops single-stepping
                                context->uc_mcontext.gregs[REG_EFL] &= ~(1LL << 8);
                        }

                        single_step(func_address); 

                        non_regular_start = false; 
                        run = 0;
                        call_count = 0;
                        write_count = 0;

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
                        }
                        i++;
                } while (i < MAX_OPERANDS && op != NULL);

                test_operand(&ud_obj, 0, context); 
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
void mimic_writes(uint64_t dest_address) {
        write_count++;
        fprintf(stderr, "writing to address: %p\n",(void*) dest_address);
        size_t size = sizeof(uint64_t); 
        //log destination of the write

        uint64_t val = *((uint64_t*)dest_address); 
        
        write_file.write((char*) &dest_address, sizeof(dest_address));
        write_file.write((char*) &val, size);
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
        case UD_R_RAX:
                return context->uc_mcontext.gregs[REG_RAX];
        case UD_R_RCX:
                return context->uc_mcontext.gregs[REG_RCX];
        case UD_R_RDX:
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
        case UD_R_EAX:
                return context->uc_mcontext.gregs[REG_EAX];
        case UD_R_AX:
                return context->uc_mcontext.gregs[REG_AX];
        case UD_R_AL:
                return context->uc_mcontext.gregs[REG_AL];
        case UD_R_AH:
                return context->uc_mcontext.gregs[REG_AH];
         case UD_R_DX:
                return context->uc_mcontext.gregs[REG_DX];
        case UD_R_DL:
                return context->uc_mcontext.gregs[REG_DL];
        case UD_R_DH:
                return context->uc_mcontext.gregs[REG_DH];             
                            
        case UD_NONE:
                return 0;
        default:
                fprintf(stderr, "32, 16 and 8bit registers are not supported yet\n");
                return 0; 
        }
}

uint32_t* get_fp_register(ud_type_t obj, ucontext_t* context) {
        switch(obj) {
        default: return context->uc_mcontext.fpregs->_xmm[0].element;
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

/**
 * Fake main that intercepts the main of a program running the analyzer tool
 * takes in the arguments passed on running 
 */
static int wrapped_main(int argc, char** argv, char** env) {
        fprintf(stderr, "Entered main wrapper\n");
        
        //storing the func_name searched for as the last argument
        string func_name = argv[argc-1];  
        argv[argc-1] = NULL;
        argc -= 1;

        func_address = find_address("/proc/self/exe", func_name);

        //set up for the SIGTRAP signal handler
        struct sigaction sig_action, debugger;
        memset(&sig_action, 0, sizeof(sig_action));
        sig_action.sa_sigaction = trap_handler;
        sigemptyset(&sig_action.sa_mask);
        sig_action.sa_flags = SA_SIGINFO;
        sigaction(SIGTRAP, &sig_action, 0);
   
        //for the debugger
        memset(&debugger, 0, sizeof(debugger));
        debugger.sa_sigaction = seg_handler;
        sigemptyset(&debugger.sa_mask);
        debugger.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &debugger, 0);

        write_count = 0;
        single_step(func_address);

        return_file.open("return-logger", fstream::out | fstream::trunc | fstream::binary);
        write_file.open("write-logger", fstream::out | fstream::trunc | fstream::binary);
                
        map<string, uint64_t> start_readings = measure_energy();
        
        og_main(argc, argv, env);

        map<string, uint64_t> end_readings = measure_energy();

        printf("Energy consumption (%lu):\n", end_readings.size());
        for(auto &ent : end_readings) {
                printf("%s: %lu\n", ent.first.c_str(), ent.second - start_readings.at(ent.first));
        }

        return_file.close();
        write_file.close();

        //switch back to old permissions
        
        return 0; 
}

/**
 * Intercepts __libc_start_main call to override main of the program calling the analyzer tool
 * Code retrieved from https://github.com/plasma-umass/coz/blob/master/libcoz/libcoz.cpp
 *                 and https://github.com/ccurtsinger/interpose
 */
extern "C" int __libc_start_main(main_fn_t main_fn, int argc, char** argv, void (*init)(),
                void (*fini)(), void (*rtld_fini)(), void* stack_end) {

        //Find original __libc_start_main
        
        auto og_libc_start_main = (decltype(__libc_start_main)*)dlsym(RTLD_NEXT, "__libc_start_main");

        //Save original main function
        og_main = main_fn;

        //Running original __libc_start_main with wrapped main
        return og_libc_start_main(wrapped_main, argc, argv, init, fini, rtld_fini, stack_end); 
}

#define _GNU_SOURCE
#include <dlfcn.h>

//citations: modified example code from
//https://github.com/aclements/libelfin/blob/master/examples/dump-syms.cc
#include "elf++.hh" //parsing the binary file 
#include "interpose.hh" //interposing exit functions
#include "x86jump.h" //jumping to function disabler
#include <udis86.h> //interpreting assembly instructions

#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <execinfo.h>
#include <fcntl.h>
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

using namespace std;

enum ReturnMode{
        INT,
        FLOAT,
        LARGE
};

fstream file; //for logging later
uint64_t func_address; //the address of the target function
ReturnMode return_mode;
uint64_t offset; //offset of the main exectuable
uint8_t func_start_byte; //the byte overwrtitten with 0xCC for single-stepping
uint64_t* stack; //a pointer to the beginning of the stack
queue<uint64_t> rets; //return values for the disabler function

typedef int (*main_fn_t)(int, char**, char**);
main_fn_t og_main;

//function declarations
static int callback(struct dl_phdr_info *info, size_t size, void *data);
void find_address(const char* file_path, string func_name);
uint64_t get_register(ud_type_t obj, ucontext_t* context);
void initialize_ud_obj(ud_t* ud_obj);
bool just_read(const ud_t* obj, unsigned int n, ucontext_t* context);
void shut_down();
void test_operand(ud_t* obj, int n);
void trap_handler(int signal, siginfo_t* info, void* cont);

/**
 * Locates the address of the target function
 * file_path: the path to the binary file
 * func_name: the name of the target function
 */
void find_address(const char* file_path, string func_name) {
        uint64_t addr = 0;

        int read_fd = open(file_path, O_RDONLY);
        if (read_fd < 0) {
                fprintf(stderr, "%s: %s\n", file_path, strerror(errno));
                exit(2);
        }

        elf::elf f(elf::create_mmap_loader(read_fd));
        for (auto &sec : f.sections()) {
                if (sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym) continue;

              
                fprintf(stderr, "Section '%s':\n", sec.get_name().c_str());
                fprintf(stderr, "%-16s %-5s %-7s %-5s %s %s\n",
                                "Address", "Size", "Binding", "Index", "Name", "Type");
                

                for (auto sym : sec.as_symtab()) {
                        auto &d = sym.get_data();
                        if (d.type() != elf::stt::func || sym.get_name() != func_name) continue;

                        
                        //probably will end up writing to log_fd
                        fprintf(stderr, "0x%-16lx %-5lx %-7s %5s %s %s\n",
                                        offset + d.value, d.size,
                                        to_string(d.binding()).c_str(),
                                        to_string(d.shnxd).c_str(),
                                        sym.get_name().c_str(),
                                        to_string(d.type()).c_str());
                        

                        addr = offset + d.value; 
                }
        }
       
        func_address = addr;
        //potential problem with multiple entries in the table for the same function? 
}

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
}

/**
 * Accesses the entry for the main executable on first execution of callback
 * Passed as a parameter to dl_iterate_phdr()
 * dl_phdr_info: a pointer to a structure containing info about the shared object 
 * size: size of the shared object 
 * data: a copy of value passed by dl_iterate_phdr();
 * @returns a non-zero value until there are no shared objects to be processed. 
 */
static int callback(struct dl_phdr_info *info, size_t size, void *data) {
        // or info->dlpi_name == "\0" if first run doesn't work ?
        static int run = 0;
        if (run) return 0;

        offset = info->dlpi_addr; 
        run = 1;
        return 0; 
}

void test_operand(ud_t* obj, int n, ucontext_t* context) {
        if (just_read(obj, n, context)) fprintf(stderr, "read in operand %d\n", n);
        else fprintf(stderr, "write in operand %d -- not supported yet\n", n);
}

void initialize_ud(ud_t* ud_obj) {
        ud_init(ud_obj);
        ud_set_mode(ud_obj, 64);
        ud_set_syntax(ud_obj, UD_SYN_ATT);
        ud_set_vendor(ud_obj, UD_VENDOR_INTEL);
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

        ucontext_t* context = reinterpret_cast<ucontext_t*>(cont);

        if (func_start_byte == 0x55) {
                fprintf(stderr, "func_start_byte is 0x55\n");
                if (!run) {
                        //Faking the %rbp stack push to account for the 0xCC byte overwrite
                        stack = (uint64_t*)context->uc_mcontext.gregs[REG_RSP];
                        uint64_t frame = (uint64_t)context->uc_mcontext.gregs[REG_RBP];

                        //needs further explanation 
                        stack--;
                        *stack = frame;
                        context->uc_mcontext.gregs[REG_RSP] = (uint64_t)stack;

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
                if(return_mode == FLOAT) {
                        uint32_t* xmm = context->uc_mcontext.fpregs->_xmm[0].element;
                        fprintf(stderr, "xmm0 value: %d, %d, %d, %d\n", xmm[0], xmm[1], xmm[2], xmm[3]);
                                
                        if(call_count < 0) {
                                fprintf(stderr, "returned from target function\n");

                                for(int i = 0; i < 4; i++) {
                                        file.write((char*) &xmm[i], sizeof(uint32_t));
                                }

                                if (!non_regular_start) {
                                        //stops single-stepping
                                        context->uc_mcontext.gregs[REG_EFL] &= ~(1LL << 8);
                                }

                                single_step(func_address); 

                                non_regular_start = false; 
                                run = 0;
                                call_count = 0;

                                return;
                        }
                } else if(return_mode == LARGE) {{
                        uint64_t rax = context->uc_mcontext.gregs[REG_RAX]; 
                        fprintf(stderr, "rdx value: %p\n", (void*)(context->uc_mcontext.gregs[REG_RDX]));
                        fprintf(stderr, "also rax value: %p\n", (void*) context->uc_mcontext.gregs[REG_RAX]);
                        //each call may have its own return, so final return will give a negative count
                        if(call_count < 0) {
                                fprintf(stderr, "returned from target function\n");
                                //logging 
                                uint32_t hval = htonl((rax >> 32) & 0xFFFFFFFF);
                                uint32_t lval = htonl(rax & 0xFFFFFFFF);
                                file.write((char*) &hval, sizeof(hval));
                                file.write((char*) &lval, sizeof(lval));

                                if (!non_regular_start) {
                                        //stops single-stepping
                                        context->uc_mcontext.gregs[REG_EFL] &= ~(1LL << 8);
                                }

                                single_step(func_address);

                                non_regular_start = false; 
                                run = 0;
                                call_count = 0;
                                return;
                        }
                }
                } else {
                        uint64_t rax = context->uc_mcontext.gregs[REG_RAX];
                        fprintf(stderr, "rax value: %lu\n", rax);
                        //each call may have its own return, so final return will give a negative count
                        if(call_count < 0) {
                                fprintf(stderr, "returned from target function\n");
                                //logging 
                                uint32_t hval = htonl((rax >> 32) & 0xFFFFFFFF);
                                uint32_t lval = htonl(rax & 0xFFFFFFFF);
                                file.write((char*) &hval, sizeof(hval));
                                file.write((char*) &lval, sizeof(lval));

                                if (!non_regular_start) {
                                        //stops single-stepping
                                        context->uc_mcontext.gregs[REG_EFL] &= ~(1LL << 8);
                                }

                                single_step(func_address);

                                non_regular_start = false; 
                                run = 0;
                                call_count = 0;
                                return;
                        }
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
                        
                //known potential writes with 2 operands
        case UD_Imov:
                fprintf(stderr, "known potential write 2 op instruction\n");
                test_operand(&ud_obj, 1, context);
                break;

        default:
                fprintf(stderr, "unknown operation, testing all operands\n");
                ud_operand_t* op;
                int i = 0;
                do {
                        if ((op = (ud_operand_t*) ud_insn_opr(&ud_obj, i)) != NULL) {
                                fprintf(stderr, "testing operand %d\n", i);
                                test_operand(&ud_obj, i, context);
                        }
                        i++;
                } while (i < MAX_OPERANDS && op != NULL);
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

/**
 * Checks if the next instruction will only read or also write to memory
 * ud_t* obj: pointer to the object that disassembles the next instruction 
 * n: the position of the operand we inspect; 0 for source, 1 for destination
 * context: context from the handler with general register information 
 * @returns bool: true if no writes to memory; false otherwise. 
 */
bool just_read(const ud_t* obj, unsigned int n, ucontext_t* context) {
        const ud_operand_t* instrct = ud_insn_opr(obj, n);
        if (instrct->type == UD_OP_MEM) {
                uint64_t mem_address; //address of the destination
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

                //calculating the memory address based on assembly register information 
                mem_address = offset +
                        get_register(instrct->base, context) +
                        (get_register(instrct->index, context)*
                         instrct->scale);

                //if the instruction tries to access memory outside of the current
                //stack frame, we know it writes to memory 
                uint64_t instr_ptr = context->uc_mcontext.gregs[REG_RIP];

                return ((uintptr_t) stack > mem_address &&
                        instr_ptr < mem_address); 
        }

        //if the instruction doesn't touch memory then it's fine
        return true;
}

/*
 * Translates from udis's register enum's to register addresses
 * obj: object containing the instruction to be disassembled
 * context: from the signal handler with general register information  
 */
uint64_t get_register(ud_type_t obj, ucontext_t* context) {
        switch(obj) {
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
        case UD_NONE:
                return 0;
        default:
                fprintf(stderr, "32, 16 and 8bit registers are not supported yet\n");
                return 0; 
        }
}

/**
 * A temporary gdb workaround debugger.
 */
void seg_handler(int sig, siginfo_t* info, void* context) {

        if (sig != SIGSEGV) {
                fprintf(stderr, "should not be here\n");
                exit(2); 
        };

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
        
<<<<<<< HEAD
        string mode = string(argv[argc-2]);
        if(mode == "float") return_mode = FLOAT;
        else if(mode == "struct") return_mode = LARGE;
        else if(mode == "int") return_mode = INT;
        else {
                fprintf(stderr, "Invalid return type mode %s\n", mode.c_str());
                exit(3);
        }
=======
        fpmode = string(argv[argc-2]).compare("fp") == 0;
        argv[argc-2] = NULL;
>>>>>>> f17b6c7224350d8c37d4b0cf4cb6b222ceddaaa9

        //storing the func_name searched for as the last argument
        string func_name = argv[argc-1];  
        argv[argc-1] = NULL;

        argc -= 2;

        dl_iterate_phdr(callback, NULL);
        find_address("/proc/self/exe", func_name);
        
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
                
        single_step(func_address);

        file.open("read-logger", fstream::out | fstream::trunc | fstream::binary);
                
        ifstream energy_file("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj", fstream::in);
        unsigned long long energy_before, energy_after;
        energy_file >> energy_before;
        
        og_main(argc, argv, env);

        energy_file.seekg(0);
        energy_file >> energy_after;

        printf("Original energy consumption: %llu\n", (energy_after-energy_before));
        energy_file.close();
        file.close();
        
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

INTERPOSE (exit)(int rc) {
        shut_down();
        real::exit(rc);
}

INTERPOSE (_exit)(int rc) {
        shut_down();
        real::_exit(rc); 
}

INTERPOSE (_Exit)(int rc) {
        shut_down();
        real::_Exit(rc); 
}

void shut_down() {
        //close(log_fd);
}

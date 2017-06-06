#define _GNU_SOURCE
#include <dlfcn.h>

//citations: modified example code from
//https://github.com/aclements/libelfin/blob/master/examples/dump-syms.cc
#include "elf++.hh"
#include "interpose.hh"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <link.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <execinfo.h>
#include <udis86.h>

#define PAGE_SIZE 4096
int log_fd;
std::uint64_t offset;
std::uint64_t address; 
uint8_t remembered_byte;
bool return_reached; 
int call_count;
uint64_t* stack;

bool just_read(const ud_t* obj, unsigned int n, ucontext_t* context);
void shut_down();
uint64_t get_register(ud_type_t obj, ucontext_t* context);

std::uint64_t find_address(const char* file_path, std::string func_name) {

        std::uint64_t addr;

        int read_fd = open(file_path, O_RDONLY);
        if (read_fd < 0) {
                fprintf(stderr, "%s: %s\n", file_path, strerror(errno));
                exit(2);
        }

        elf::elf f(elf::create_mmap_loader(read_fd));
        for (auto &sec : f.sections()) {
                if (sec.get_hdr().type != elf::sht::symtab) continue;

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

        return addr; 
}

void single_step(std::uint64_t func_address) {

        std::uint64_t page_start = func_address & ~(PAGE_SIZE-1) ;

        //making the page writable, readable and executable
        if (-1 == mprotect((void*) page_start, PAGE_SIZE, PROT_READ| PROT_WRITE| PROT_EXEC)) {
                fprintf(stderr, "%s\n", strerror(errno));
                exit(2); 
        }


        //setting the last byte to 0xCC causes a SIGTRAP signal for single-stepping
        uint8_t* function_bytes = (uint8_t*)func_address;
        remembered_byte = function_bytes[0];
        function_bytes[0] = 0xCC;
}
//returns the entry for the main executable on first execution of callback
// or info->dlpi_name == "\0" ?
static int callback(struct dl_phdr_info *info, size_t size, void *data) {

        static int run = 0;

        if (run) return 0;

        offset = info->dlpi_addr; 
        run = 1;
        return 0; 
}

typedef int (*main_fn_t)(int, char**, char**);
main_fn_t og_main;

void handler(int signal, siginfo_t* info, void* cont) {
        fprintf(stderr, "trap handler\n");
        if (signal != SIGTRAP) exit(2);
        //fprintf(stderr, "caught SIGTRAP\n");

        static int run = 0;

        // process assembly instruction info w m_context
        ucontext_t* context = reinterpret_cast<ucontext_t*>(cont);
        //fprintf(stderr, "hi\n");
        //address of the next assembly instruction to be executed
        //fprintf(stderr, "Stack starts at: 0x%llx\n", context->uc_mcontext.gregs[REG_RBP]);
        //fprintf(stderr, "hi2\n");


        if (remembered_byte == 0x55) {
                fprintf(stderr, "if\n");
                if (!run) {
                        fprintf(stderr, "Entered only once\n");
                        // Fake the push %rbp instruction
                        stack = (uint64_t*)context->uc_mcontext.gregs[REG_RSP];
                        uint64_t frame = (uint64_t)context->uc_mcontext.gregs[REG_RBP];
                        stack--;
                        *stack = frame;
                        context->uc_mcontext.gregs[REG_RSP] = (uint64_t)stack;

                        run = 1; 
                }

                ud_t ud_obj;
                ud_init(&ud_obj);

                ud_set_mode(&ud_obj, 64);
                ud_set_syntax(&ud_obj, UD_SYN_ATT);
                ud_set_vendor(&ud_obj, UD_VENDOR_INTEL);

                ud_set_input_buffer(&ud_obj, (uint8_t*) context->uc_mcontext.gregs[REG_RIP], 18);
                fprintf(stderr, "disassembling\n");
                fprintf(stderr, "disassembled: %x\n", ud_disassemble(&ud_obj));

                // different processing for read/write
                // with writing to memory, the writes will be outside of the current stack frame : stack base -> current pointer 
                        
                //returning the value 
                if (return_reached) {
                        // RAX won't hold large values ! 
                        fprintf(stderr, "return reached: %lld\n", context->uc_mcontext.gregs[REG_RAX]);
                        call_count--;
                        return_reached = false;
                        if(call_count < 0) {
                                fprintf(stderr, "call_count < 0, ending\n");
                                fprintf(stderr, "rax: %lld\n", context->uc_mcontext.gregs[REG_RAX]);
                                context->uc_mcontext.gregs[REG_EFL] &= ~(1LL << 8);
                                return;
                        }
                }

                fprintf(stderr, "here: %s\n", ud_insn_asm(&ud_obj));

                switch (ud_insn_mnemonic(&ud_obj)) {
                        case UD_Iret:
                                fprintf(stderr, "found return\n");
                                return_reached = true;
                                break;

                        case UD_Icall:
                                fprintf(stderr, "found call\n");
                                call_count++;
                                break;

                        case UD_Imov:
                                fprintf(stderr, "writing to memory\n");
                                // memory writes
                                //if not writable call write
                                if (just_read (&ud_obj, 1, context)) fprintf(stderr, "sucess"); 
                                break; 
                        default: break;
                }

                context->uc_mcontext.gregs[REG_EFL] |= 1 << 8;
                fprintf(stderr, "end if\n");
                //check it only reads 
        } else {
                fprintf(stderr, "else\n");
                // Put back the original byte (0x55 only)
                //uint8_t* ip = (uint8_t*)(context->uc_mcontext.gregs[REG_RIP] - 1);
                //*ip = 0x55;
                //context->uc_mcontext.gregs[REG_RIP]--;
        }
}

bool just_read(const ud_t* obj, unsigned int n, ucontext_t* context) {
        uint64_t mem_address;
        const ud_operand_t* instrct = ud_insn_opr(obj, n); 
        if (instrct->type == UD_OP_MEM) { // 1 is the right side of the instruction (destination)

                int64_t offset; 
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
                default:
                        offset = (int64_t) instrct->lval.sqword;
                        break;
                }

                mem_address = offset +
                              get_register(instrct->base, context) +
                              (get_register(instrct->index, context)*
                                        instrct->scale);

                uint64_t curr_address = context->uc_mcontext.gregs[REG_RIP];

                return ((uintptr_t) stack > mem_address &&
                        curr_address < mem_address); 
        }

        return true;
}

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
                fprintf(stderr, "32, 16 and 8bit registers are not supported yet");
                //fprintf(stderr, obj); //?
                exit(2); 
        }
}

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

        void* bt[1];
        bt[0] = (void*) ((ucontext_t*) context)->uc_mcontext.gregs[REG_RIP];

        backtrace_symbols_fd(bt, 1, STDOUT_FILENO);
}




static int wrapped_main(int argc, char** argv, char** env) {
        fprintf(stderr, "Entered main wrapper\n");

        call_count = 0;

        //set up for the signal handler
        struct sigaction sig_action, debugger;
        memset(&sig_action, 0, sizeof(sig_action));
        sig_action.sa_sigaction = handler;
        sigemptyset(&sig_action.sa_mask);
        sig_action.sa_flags = SA_SIGINFO;
        sigaction(SIGTRAP, &sig_action, 0);

        memset(&debugger, 0, sizeof(debugger));
        debugger.sa_sigaction = seg_handler;
        sigemptyset(&debugger.sa_mask);
        debugger.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &debugger, 0);

        //storing the func_name searched for as the last argument
        std::string func_name = argv[argc-1];  
        argv[argc-1] = NULL;

        //getting the address of the main executable for the offset 
        dl_iterate_phdr(callback, NULL);

        fprintf(stderr, "finding address\n");
        address = find_address("/proc/self/exe", func_name);

        fprintf(stderr, "single stepping\n");
        single_step(address);

        fprintf(stderr, "running og main\n");
        og_main(argc, argv, env);

        fprintf(stderr, "exiting\n");
        return 0; 
}


//Code retrieved from https://github.com/plasma-umass/coz/blob/master/libcoz/libcoz.cpp
//                and https://github.com/ccurtsinger/interpose
extern "C" int __libc_start_main(main_fn_t main_fn, int argc, char** argv, void (*init)(),
                void (*fini)(), void (*rtld_fini)(), void* stack_end) {

        //Find original __libc_start_main
        auto og_libc_start_main = (decltype(__libc_start_main)*)dlsym(RTLD_NEXT, "__libc_start_main");

        //Save original main function
        og_main = main_fn;

        //Running original __libc_start_main with wrapped main
        return og_libc_start_main(wrapped_main, argc, argv, init, fini, rtld_fini, stack_end); 
}

//Code retrieved from Mattori & 213 partners
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

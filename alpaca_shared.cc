#include "alpaca_shared.hh"

#include "alpaca_no2.hh"
#include "alpaca_fn_disabler.hh"

#include <iomanip>
#include <malloc.h>
#include <execinfo.h>
uint64_t offset;

uint64_t func_address; //the address of the target function

FILE* return_file;
FILE* write_file;
FILE* sys_file;
FILE* local_sys_file;
FILE* ret_addr_file;

//the byte overwrtitten with 0xCC for single-stepping, used in analyzer
uint8_t start_byte;

//keep track if there are any wrong writes
uint64_t wrong_writes;

//the beginning of the stack for the targeted function
uint64_t* stack_base; 

typedef int (*main_fn_t)(int, char**, char**);
main_fn_t og_main;

#define OUT_FMODE "wb"
#define IN_FMODE "rb"


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
  exit(5);
}

void setup_segv_handler() {
  DEBUG("Enabling segfault handler!");
  struct sigaction sig_action;
  memset(&sig_action, 0, sizeof(sig_action));
  sig_action.sa_sigaction = seg_handler;
  sigemptyset(&sig_action.sa_mask);
  sig_action.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sig_action, 0);
}


/**
 * Enables single-stepping (instruction by instruction) through the function
 * address: (virtual) address of the function in memory
 */
uint8_t single_step(uint64_t address) {
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
  uint8_t start_byte = ((uint8_t*)address)[0];
  DEBUG("The original starting byte: " << int_to_hex(start_byte));
  ((uint8_t*)address)[0] = 0xCC;
  DEBUG("Finished enabling single step");
  return start_byte;
}

void setup_alt_stack() {
  stack_t ss;

  ss.ss_sp = malloc(SIGSTKSZ);
  if (ss.ss_sp == NULL) {
    cerr << "Could not set up alt stack, ss_sp is null!\n";
    exit(3);
  }
  ss.ss_size = SIGSTKSZ;
  ss.ss_flags = 0;
  if (sigaltstack(&ss, NULL) == -1) {
    cerr << "Could not set up alt stack, sigaltstack returned -1!\n";
    exit(3);
  }
}

void setup_analyzer() {
  struct sigaction sig_action;
  memset(&sig_action, 0, sizeof(sig_action));
  sig_action.sa_sigaction = trap_handler;
  sigemptyset(&sig_action.sa_mask);
  sig_action.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigaction(SIGTRAP, &sig_action, 0);
  setup_alt_stack();

  start_byte = single_step(func_address);
}

void setup_disabler() {
  read_syscalls();
  read_local_syscalls();
  read_writes();
  read_returns();
  setup_disabler_jump();
}

void setup_check() {
  struct sigaction sig_action;
  memset(&sig_action, 0, sizeof(sig_action));
  sig_action.sa_sigaction = check_trap_handler;
  sigemptyset(&sig_action.sa_mask);
  sig_action.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigaction(SIGTRAP, &sig_action, 0);
  setup_alt_stack();

  start_byte = single_step(func_address);

  read_syscalls();
  read_writes();
  read_returns();
  read_ret_addrs();
}

void open_logs(const char* mode) {
  return_file = fopen("return-logger", mode);
  if(return_file == NULL) {
    cerr << "Error opening return log: " << strerror(errno);
    exit(4);
  }
  setbuf(return_file, NULL);
  write_file = fopen("write-logger", mode);
  if(write_file == NULL) {
    cerr << "Error opening write log: " << strerror(errno);
    exit(4);
  }
  setbuf(return_file, NULL);
  sys_file = fopen("sys-logger", mode);
  if(sys_file == NULL) {
    cerr << "Error opening sys log: " << strerror(errno);
    exit(4);
  }
  setbuf(sys_file, NULL);
  local_sys_file = fopen("local-sys-logger", mode);
  if(local_sys_file == NULL) {
    cerr << "Error opening local-sys log: " << strerror(errno);
    exit(4);
  }
  setbuf(local_sys_file, NULL);
  ret_addr_file = fopen("ret-addr-logger", mode);
  if(ret_addr_file == NULL) {
    cerr << "Error opening ret-addr log: " << strerror(errno);
    exit(4);
  }
  setbuf(ret_addr_file, NULL);
}

void check_self_maps() {
  char self_maps[1024*1024] = {0};
  FILE* self_maps_f = fopen("/proc/self/maps", "r");
  fread(self_maps, 1024*1024, 1, self_maps_f);
  fclose(self_maps_f);
  DEBUG(self_maps);
}

void wait_at_startup(){
  DEBUG("Alpaca started, waiting for user input to continue");
  char *getline_buf = NULL;
  size_t getline_size;
  getline(&getline_buf, &getline_size, stdin);
}

static int wrapped_main(int argc, char** argv, char** env) {
  //wait_at_startup();
  DEBUG("Entered Alpaca's main");
  setup_segv_handler();
  wrong_writes = 0;
  
  //storing the func_name searched for as the last argument
  char alpaca_mode[256], func_name[256], energy_ppid[256];

  if(getenv("ALPACA_MODE") == NULL) {
    cerr << "Environment variables not set correctly (ALPACA_MODE not set)!\n";
    exit(2);
  }
  if(getenv("ALPACA_FUNC") == NULL) {
    cerr << "Environment variables not set correctly (ALPACA_FUNC not set)!\n";
    exit(2);
  }
  if(getenv("ALPACA_PPID") == NULL) {
    cerr << "Environment variables not set correctly (ALPACA_PPID not set)!\n";
    exit(2);
  }
  strcpy(alpaca_mode, getenv("ALPACA_MODE"));
  strcpy(func_name, getenv("ALPACA_FUNC"));
  strcpy(energy_ppid, getenv("ALPACA_PPID"));
  DEBUG("The mode is " << alpaca_mode);
  DEBUG("The target function is " << func_name);

  //check_self_maps(); 

  func_address = find_address("/proc/self/exe", func_name);
  if (func_address == 0) {
    DEBUG("Could not find the function address, running it normally");
    return og_main(argc, argv, env);
  }
  DEBUG("The address of the target function is " << int_to_hex(func_address));
    
  if (strcmp(alpaca_mode, "a") == 0) {
    DEBUG("Analyze mode");
    
    open_logs(OUT_FMODE);

    setup_analyzer();                
  } else if (strcmp(alpaca_mode, "d") == 0) {
    DEBUG("Disable mode");
    
    open_logs(IN_FMODE);

    setup_disabler();
  } else if (strcmp(alpaca_mode, "c") == 0) {
    DEBUG("Check mode");

    open_logs(IN_FMODE);

    setup_check();
  } else {
    cerr << "Unknown mode!\n";
    exit(2);
  }

  DEBUG("File pointers: " << int_to_hex((uint64_t)return_file) << ", " << int_to_hex((uint64_t)write_file) << ", " << int_to_hex((uint64_t)sys_file) << ", " << int_to_hex((uint64_t)ret_addr_file));

  setbuf(stdout, NULL);
  
  int ppid = atoi(energy_ppid);

  const union sigval val = {0};
  if (strcmp(alpaca_mode, "d") == 0) sigqueue(ppid, SIGUSR1, val);
  int main_return = og_main(argc, argv, env);
  if (strcmp(alpaca_mode, "d") == 0) sigqueue(ppid, SIGUSR1, val);

  //check_self_maps();
  cerr << "Wrong writes: " << wrong_writes << "\n";

  DEBUG("File pointers: " << int_to_hex((uint64_t)return_file) << ", " << int_to_hex((uint64_t)write_file) << ", " << int_to_hex((uint64_t)sys_file) << ", " << int_to_hex((uint64_t)ret_addr_file));
  
  fclose(return_file);
  fclose(write_file);
  fclose(sys_file);
  fclose(local_sys_file);
  fclose(ret_addr_file);
  
  return main_return;
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
  static int run = 0;
  if (run) return 0;

  offset = info->dlpi_addr; 
  run = 1;
  return 0; 
}

/*
 * Find the address of the targeted function
 */

uint64_t find_address(const char* file_path, string func_name) {
  dl_iterate_phdr(callback, NULL);
        
  uint64_t addr = 0;

  int read_fd = open(file_path, O_RDONLY);
  if (read_fd < 0) {
    cerr << "error reading " << file_path << ": " << strerror(errno) << "\n";
    exit(2);
  }

  shared_ptr<elf::loader> file_map = elf::create_mmap_loader(read_fd);   
  elf::elf f(file_map);
  for (auto &sec : f.sections()) {
    if (sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym) continue;

    for (auto sym : sec.as_symtab()) {
      auto &d = sym.get_data();
      if (d.type() != elf::stt::func || sym.get_name() != func_name) continue;

      addr = offset + d.value; 
    }
  }

  close(read_fd);
  return addr;
}


void initialize_ud(ud_t* ud_obj) {
  DEBUG("Initializing the udis86 object");
  ud_init(ud_obj);
  ud_set_mode(ud_obj, 64);
  ud_set_syntax(ud_obj, UD_SYN_ATT);
  ud_set_vendor(ud_obj, UD_VENDOR_ANY);
  DEBUG("Finished initializing the udis86 object");
}

/*
 *Display the addresses in hexadecimal
 */
char* int_to_hex(uint64_t i) {
  static char buf[15];
  snprintf(buf, 15, "%#014lx", i);
  return buf;
}

/**
 *Prints the content of the registers when debugging 
 */

void debug_registers(ucontext_t* context) {
  return;
  DEBUG("Debugging registers");
  int regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI,
                REG_RDI, REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
  const char* reg_n[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8",
                         "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
  for(int i = 0; i < 16; i++) {
    char buf[256];
    snprintf(buf, 256, "Value of %s: %s\n", reg_n[i], int_to_hex((uint64_t)context->uc_mcontext.gregs[regs[i]]));
    fputs(buf, stderr);
  }
  const char* fpreg_n[] = {"xmm0", "xmm1"};
  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 16; j++) {
      char buf[256];
      snprintf(buf, 256, "Value of %s at byte %d: %hhu\n", fpreg_n[i], j, ((uint8_t*)context->uc_mcontext.fpregs->_xmm[i].element)[j]);
      fputs(buf, stderr);
    }
  }
}
/*
 *Write data to a file pointer
 */

void writef(char* data, size_t size, FILE* file) {
  char fname[256];
  uint64_t rf = (uint64_t) return_file, wf = (uint64_t) write_file, sf = (uint64_t) sys_file, lsf = (uint64_t) local_sys_file, raf = (uint64_t) ret_addr_file, f = (uint64_t) file;
  if(f == rf) strcpy(fname, "return_file");
  else if(f == wf) strcpy(fname, "write_file");
  else if(f == sf) strcpy(fname, "sys_file");
  else if(f == raf) strcpy(fname, "ret_addr_file");
  else if(f == lsf) strcpy(fname, "local_sys_file");
  else strcpy(fname, "invalid");
  for(int i = 0; i < size; i++) DEBUG("Data: " << int_to_hex((uint64_t)data[i]));
  DEBUG("Data to " << fname << " as uint64_t: " << int_to_hex(*(uint64_t*)data));
  for(int i = 0; i < size; i++) DEBUG("fputc wrote " << fputc(data[i], file) << " (data[" << i << "])");
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

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
FILE* ret_addr_file;

//the byte overwrtitten with 0xCC for single-stepping, used in analyzer
uint8_t start_byte;

uint64_t wrong_writes;

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
  while(1){}
  int j, nptrs; 
  void* buffer[200];
  char** strings;
//  signal(sig, SIG_DFL);
  nptrs = backtrace(buffer, 200);

  backtrace_symbols_fd(buffer, nptrs, STDERR_FILENO);
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
 * func_address: (virtual) address of the function in memory
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

void test_malloc(){
        size_t size_arr[7] = {16, 32, 64, 128, 256, 512, 1024}; 
        cerr << "Checking malloc calls\n";

        for(int i =0; i< 7; i++){
                char* test = (char*)malloc(sizeof(char)*size_arr[i]);
                cerr << "Malloced: " << int_to_hex((uint64_t)test) << " ;usable size: " << malloc_usable_size(test) << "\n";
        }
}

static int wrapped_main(int argc, char** argv, char** env) {
  //test_malloc();
  /*DEBUG("Alpaca started, waiting for user input to continue");
  char *getline_buf = NULL;
  size_t getline_size;
  getline(&getline_buf, &getline_size, stdin);*/
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

  check_self_maps(); 

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

  /*
  DEBUG("Gathering starting readings");
  energy_reading_t start_readings[NUM_ENERGY_READINGS];
  int start_readings_num = measure_energy(start_readings, NUM_ENERGY_READINGS);
  cerr << "Starting target program\n";
  */
  //test_malloc();
  int ppid = atoi(energy_ppid);
  
  if (strcmp(alpaca_mode, "d") == 0) kill(ppid, SIGUSR1);
  int main_return = og_main(argc, argv, env);
  if (strcmp(alpaca_mode, "d") == 0) kill(ppid, SIGUSR1);
  
  fflush(stdout);
  fflush(stderr);
  fflush(return_file);
  fflush(write_file);
  fflush(sys_file);
  fflush(ret_addr_file);
  //test_malloc();
  /*
  DEBUG("Gathering end readings");
  energy_reading_t end_readings[NUM_ENERGY_READINGS];
  int end_readings_num = measure_energy(end_readings, NUM_ENERGY_READINGS);

  cerr << "Energy consumption (" << dec << end_readings_num << ")\n";
  for(int i = 0; i < end_readings_num; i++) {
    cerr << end_readings[i].zone << ": " << dec << end_readings[i].energy - start_readings[i].energy << "\n";
  }
  */
  
  //test_malloc();
  check_self_maps();
  cerr << "Wrong writes: " << wrong_writes << "\n";

    DEBUG("File pointers: " << int_to_hex((uint64_t)return_file) << ", " << int_to_hex((uint64_t)write_file) << ", " << int_to_hex((uint64_t)sys_file) << ", " << int_to_hex((uint64_t)ret_addr_file));
  
  //test_malloc();
  //fclose(return_file);
  //fclose(write_file);
  //fclose(sys_file);
  //fclose(ret_addr_file);
  
  //test_malloc();
  if (strcmp(alpaca_mode, "d") == 0) kill(ppid, SIGUSR2);
  return main_return;
}

void shut_down() {
  //to be implemented
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

    // advanced ELF information about functions
    /*fprintf(stderr, "Section '%s':\n", sec.get_name().c_str());
    fprintf(stderr, "%-16s %-5s %-7s %-5s %s %s\n",
    "Address", "Size", "Binding", "Index", "Name", "Type");*/
                

    for (auto sym : sec.as_symtab()) {
      auto &d = sym.get_data();
      if (d.type() != elf::stt::func || sym.get_name() != func_name) continue;

      /*fprintf(stderr, "0x%-16lx %-5lx %-7s %5s %s %s\n",
              offset + d.value, d.size,
              to_string(d.binding()).c_str(),
              to_string(d.shnxd).c_str(),
              sym.get_name().c_str(),
              to_string(d.type()).c_str());*/
                        

      addr = offset + d.value; 
    }
  }

  close(read_fd);
  return addr;
  //potential problem with multiple entries in the table for the same function? 
}

/**
 *Reads up to max bytes from path into contents
 *@return number of bytes read
 */

int file_readline(char path[], char contents[], int max) {
  memset(contents, 0, max);
  FILE* in = fopen(path, "r");
  int count = fread(contents, max, 1, in);
  *strstr(contents, "\n") = '\0';
  return count;
}

/**
 *finds up to max files and directories in dir with substring substr into results
 *@return the number of results
 */

int find_in_dir(const char dir[], const char substr[], char results[][256], int max) {
  int ind = 0;
  cerr << "Directory being searched: " << dir << "\n"; 
  DIR* dirp = opendir(dir); //???????????????????????????
  struct dirent* dp;
  while((dp = readdir(dirp)) != NULL && ind < max) {
    strcpy(results[ind], dp->d_name);
    if(strstr(results[ind], substr) != NULL) {
      ind++;
    }
  }
  closedir(dirp);
  return ind;
}

/**
 *reads from the energy zone name and usage files
 *@return a struct with the name and the energy usage
 */

energy_reading_t get_energy_info(char dir[]) {
  // build name file path
  char name[MAX_ENERGY_READING]; 
  size_t ename_len = strlen(dir) + strlen(ENERGY_NAME) + 1;
  char ename[ename_len];
  snprintf(ename, ename_len, "%s%s", dir, ENERGY_NAME);
  file_readline(ename, name, MAX_ENERGY_READING);
  
  // build energy usage file path      
  char energy_str[MAX_ENERGY_READING];
  size_t efile_len = strlen(dir) + strlen(ENERGY_FILE) + 1;
  char efile[efile_len];
  snprintf(efile, efile_len, "%s%s", dir, ENERGY_FILE);
  file_readline(efile, energy_str, MAX_ENERGY_READING);
  uint64_t energy = strtoul(energy_str, NULL, 10);
        
  energy_reading_t reading = { name, energy };
  return reading; 
}

/**
 *measures the energy of up to max zones/subzones into readings
 *@return the number of zones/subzones measured 
 */

int measure_energy(energy_reading_t* readings, int max) {
  int ind = 0;
  char powerzones[MAX_POWERZONES][256];
  int num_zones = find_in_dir(ENERGY_ROOT, "intel-rapl:", powerzones, MAX_POWERZONES);
  
  for(int i = 0; i < num_zones && ind < max; i++) {
    char* zone = powerzones[i];

    // build the zone directory path
    size_t zonedir_len = strlen(ENERGY_ROOT) + strlen(zone) + 2;
    char zonedir[zonedir_len];
    snprintf(zonedir, zonedir_len, "%s%s/", ENERGY_ROOT, zone);
    readings[ind++] = get_energy_info(zonedir);
    
    char subzones[MAX_POWERZONES][256];
    int num_subzones = find_in_dir(zonedir, zone, subzones, MAX_POWERZONES);
    
    for(int j = 0; j < num_subzones && ind < max; j++) {
      // build the subzone directory path
      size_t subzonedir_len = strlen(zonedir) + strlen(subzones[j]) + 2;
      char subzonedir[subzonedir_len];
      snprintf(subzonedir, subzonedir_len, "%s%s/", zonedir, subzones[j]);
      readings[ind++] = get_energy_info(subzonedir);
    }
  }
  return ind;
}

void initialize_ud(ud_t* ud_obj) {
  DEBUG("Initializing the udis86 object");
  ud_init(ud_obj);
  ud_set_mode(ud_obj, 64);
  ud_set_syntax(ud_obj, UD_SYN_ATT);
  ud_set_vendor(ud_obj, UD_VENDOR_ANY);
  DEBUG("Finished initializing the udis86 object");
}

char* int_to_hex(uint64_t i) {
  // hacky debug code
  static char buf[15];
  snprintf(buf, 15, "%#014lx", i);
  return buf;
}

void debug_registers(ucontext_t* context) {
  DEBUG("Debugging registers");
  int regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI,
                REG_RDI, REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
  const char* reg_n[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8",
                         "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
  for(int i = 0; i < 16; i++) {
    char buf[256];
    snprintf(buf, 256, "Value of %s: %s\n", reg_n[i], int_to_hex((uint64_t)context->uc_mcontext.gregs[regs[i]]));
    //fputs(buf, stderr);
  }
  ;
  const char* fpreg_n[] = {"xmm0", "xmm1"};
  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 16; j++) {
      char buf[256];
      snprintf(buf, 256, "Value of %s at byte %d: %hhu\n", fpreg_n[i], j, ((uint8_t*)context->uc_mcontext.fpregs->_xmm[i].element)[j]);
      //fputs(buf, stderr);
    }
  }
}

void writef(char* data, size_t size, FILE* file) {
  char fname[256];
  uint64_t rf = (uint64_t) return_file, wf = (uint64_t) write_file, sf = (uint64_t) sys_file, raf = (uint64_t) ret_addr_file, f = (uint64_t) file;
  if(f == rf) strcpy(fname, "return_file");
  else if(f == wf) strcpy(fname, "write_file");
  else if(f == sf) strcpy(fname, "sys_file");
  else if(f == raf) strcpy(fname, "ret_addr_file");
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

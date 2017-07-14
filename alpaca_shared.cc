#include "alpaca_shared.hh"

#include "alpaca_no2.hh"
#include "alpaca_fn_disabler.hh"

#include <iomanip>

uint64_t offset;

uint64_t func_address; //the address of the target function

fstream return_file;
fstream write_file;
fstream sys_file;
fstream ret_addr_file;

//the byte overwrtitten with 0xCC for single-stepping, used in analyzer
uint8_t start_byte;

typedef int (*main_fn_t)(int, char**, char**);
main_fn_t og_main;

#define OUT_FMODE fstream::out | fstream::trunc | fstream::binary
#define IN_FMODE fstream::in | fstream::binary

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

void setup_analyzer() {
  struct sigaction sig_action;
  memset(&sig_action, 0, sizeof(sig_action));
  sig_action.sa_sigaction = trap_handler;
  sigemptyset(&sig_action.sa_mask);
  sig_action.sa_flags = SA_SIGINFO;
  sigaction(SIGTRAP, &sig_action, 0);

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
  sig_action.sa_flags = SA_SIGINFO;
  sigaction(SIGTRAP, &sig_action, 0);

  read_syscalls();
  read_writes();
  read_returns();
  read_ret_addrs();
}

void open_logs(fstream::openmode mode) {
  return_file.open("return-logger", mode);
  if(return_file.fail()) {
    cerr << "Error opening return log: " << strerror(errno);
    exit(4);
  }
  write_file.open("write-logger", mode);
  if(write_file.fail()) {
    cerr << "Error opening write log: " << strerror(errno);
    exit(4);
  }
  sys_file.open("sys-logger", mode);
  if(sys_file.fail()) {
    cerr << "Error opening sys log: " << strerror(errno);
    exit(4);
  }
  ret_addr_file.open("ret_addr-logger", mode);
  if(ret_addr_file.fail()) {
    cerr << "Error opening ret_addr log: " << strerror(errno);
    exit(4);
  }
  
}

void check_self_maps() {
  char self_maps[1024*1024] = {0};
  ifstream self_maps_f("/proc/self/maps");
  self_maps_f.read(self_maps, 1024*1024);
  self_maps_f.close();
  cerr << self_maps << "\n";
}

static int wrapped_main(int argc, char** argv, char** env) {
  DEBUG("Entered Alpaca's main");
  
  //storing the func_name searched for as the last argument
  char alpaca_mode[256], func_name[256];

  strcpy(alpaca_mode, getenv("ALPACA_MODE"));
  strcpy(func_name, getenv("ALPACA_FUNC"));
  DEBUG("The mode is " << alpaca_mode);
  DEBUG("The target function is " << func_name);

  check_self_maps();

  func_address = find_address("/proc/self/exe", func_name);
  if (func_address == 0) {
    DEBUG("Could not find the function address, running it normally");
    return og_main(argc, argv, env);
  }
  DEBUG("The address of the target function is " << int_to_hex(func_address));
    
  if (strcmp(alpaca_mode, "analyze") == 0) {
    DEBUG("Analyze mode");
    
    open_logs(OUT_FMODE);

    setup_analyzer();                
  } else if (strcmp(alpaca_mode, "disable") == 0) {
    DEBUG("Disable mode");
    
    open_logs(IN_FMODE);

    setup_disabler();
  } else if (strcmp(alpaca_mode, "check") == 0) {
    DEBUG("Check mode");

    open_logs(IN_FMODE);

    setup_check();
  } else {
    cerr << "Unknown mode!\n";
    exit(2);
  }

  /**
  DEBUG("Gathering starting readings");
  energy_reading_t start_readings[NUM_ENERGY_READINGS];
  int start_readings_num = measure_energy(start_readings, NUM_ENERGY_READINGS);
  cerr << "Starting target program\n";
  **/
  int main_return = og_main(argc, argv, env);
  /**
  DEBUG("Gathering end readings");
  energy_reading_t end_readings[NUM_ENERGY_READINGS];
  int end_readings_num = measure_energy(end_readings, NUM_ENERGY_READINGS);

  cerr << "Energy consumption (" << dec << end_readings_num << ")\n";
  for(int i = 0; i < end_readings_num; i++) {
    cerr << end_readings[i].zone << ": " << dec << end_readings[i].energy - start_readings[i].energy << "\n";
  }
  **/

  check_self_maps();
  
  return_file.close();
  write_file.close();
  sys_file.close();
  ret_addr_file.close(); 

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
  ifstream in(path);
  in.read(contents, max);
  *strstr(contents, "\n") = '\0';
  return in.gcount();
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

char* int_to_hex(uint64_t i) {
  // hacky debug code
  static char buf[15];
  snprintf(buf, 15, "%#014lx", i);
  return buf;
}

INTERPOSE (exit)(int rc) {
  cerr << "Program exited through exit() function\n";
  real::exit(rc);
}

INTERPOSE (_exit)(int rc) {
  cerr << "Program exited through _exit() function\n";
  real::_exit(rc); 
}

INTERPOSE (_Exit)(int rc) {
  cerr << "Program exited through _Exit() function\n";
  real::_Exit(rc); 
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

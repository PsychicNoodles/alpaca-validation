#include "alpaca_shared.hh"

#include "alpaca_no2.hh"
#include "alpaca_fn_disabler.hh"

uint64_t offset;

uint64_t func_address; //the address of the target function

fstream return_file;
fstream write_file;
fstream sys_file;

typedef int (*main_fn_t)(int, char**, char**);
main_fn_t og_main;

static int wrapped_main(int argc, char** argv, char** env) {
  cerr << "Entered main wrapper\n";
  
  //storing the func_name searched for as the last argument
  string func_name = argv[argc-2];  
  argv[argc-2] = NULL;

  func_address = find_address("/proc/self/exe", func_name);
        
  if (strcmp(argv[argc-1], "analyze") == 0) {
    return_file.open("return-logger", fstream::out | fstream::trunc | fstream::binary);
    write_file.open("write-logger", fstream::out | fstream::trunc | fstream::binary);
    sys_file.open("sys-logger", fstream::out | fstream::trunc | fstream::binary);
    //set up for the SIGTRAP signal handler
    struct sigaction sig_action, debugger;
    memset(&sig_action, 0, sizeof(sig_action));
    sig_action.sa_sigaction = trap_handler;
    sigemptyset(&sig_action.sa_mask);
    sig_action.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &sig_action, 0);

    single_step(func_address);
                
  } else if (strcmp(argv[argc-1], "disable") == 0) {
    return_file.open("return-logger", fstream::in | fstream::binary);
    write_file.open("write-logger", fstream::in | fstream::binary);
    sys_file.open("sys-logger", fstream::in | fstream::binary);

    read_syscalls();
    read_writes();
    read_returns();
                
                
  } else {
    cerr << "Unknown mode!\n";
    exit(2);
  }

  argc -= 2;

  energy_reading_t start_readings[NUM_ENERGY_READINGS];
  int start_readings_num = measure_energy(start_readings, NUM_ENERGY_READINGS);
  og_main(argc, argv, env);
  energy_reading_t end_readings[NUM_ENERGY_READINGS];
  int end_readings_num = measure_energy(end_readings, NUM_ENERGY_READINGS);

  cerr << "Energy consumption (" << end_readings_num << ")\n";
  for(int i = 0; i < end_readings_num; i++) {
    cerr << end_readings[i].zone << ": " << end_readings[i].energy - start_readings[i].energy << endl;
  }
        
  return_file.close();
  write_file.close();
  sys_file.close();

  return 0; 
        
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
       
  return addr;
  //potential problem with multiple entries in the table for the same function? 
}

int file_readline(char* path, char* contents, int max) {
  memset(contents, 0, max);
  ifstream in(path);
  in.read(contents, max);
  *strstr(contents, "\n") = '\0';
  return in.gcount();
}

int find_in_dir(char* dir, char* substr, char* results[], int max) {
  int ind = 0;
  DIR* dirp = opendir(dir);
  struct dirent* dp;
  while((dp = readdir(dirp)) != NULL && ind < max) {
    char* path = (char*)malloc(strlen(dp->d_name) + 1);
    strcpy(path, dp->d_name);
    if(strstr(path, substr) != NULL) {
            results[ind++] = path;
    }
  }
  closedir(dirp);
  return ind;
}

energy_reading_t push_energy_info(char* dir) {
        char* name = (char*)malloc(sizeof(char)*MAX_ENERGY_READING);
        size_t ename_len = strlen(dir) + strlen(ENERGY_NAME) + 1;
        char ename[ename_len];
        snprintf(ename, ename_len, "%s%s", dir, ENERGY_NAME);
        file_readline(ename, name, MAX_ENERGY_READING);
        char* energy_str = (char*)malloc(sizeof(char)*MAX_ENERGY_READING);
        size_t efile_len = strlen(dir) + strlen(ENERGY_FILE) + 1;
        char efile[efile_len];
        snprintf(efile, efile_len, "%s%s", dir, ENERGY_FILE);
        file_readline(efile, energy_str, MAX_ENERGY_READING);
        uint64_t energy = strtoul(energy_str, NULL, 10);
        
        energy_reading_t reading = { name, energy };
        return reading; 
}

int measure_energy(energy_reading_t* readings, int max) {
  int ind = 0;
  char* powerzones[MAX_POWERZONES];
  // char* literals in c++11 force the const qualifier
  int num_zones = find_in_dir((char*) ENERGY_ROOT, (char*) "intel-rapl:", powerzones, MAX_POWERZONES);
  for(int i = 0; i < num_zones && ind < max; i++) {
          char* zone = powerzones[i];
          size_t zonedir_len = strlen(ENERGY_ROOT) + strlen(zone) + 2;
          char zonedir[zonedir_len];
          snprintf(zonedir, zonedir_len, "%s%s/", ENERGY_ROOT, zone);
          readings[ind++] = push_energy_info(zonedir);
          char* subzones[MAX_POWERZONES];
          int num_subzones = find_in_dir(zonedir, zone, subzones, MAX_POWERZONES);
          for(int j = 0; j < num_subzones && ind < max; j++) {
                  size_t subzonedir_len = strlen(zonedir) + strlen(subzones[j]) + 2;
                  char subzonedir[subzonedir_len];
                  snprintf(subzonedir, subzonedir_len, "%s%s/", zonedir, subzones[j]);
                  readings[ind++] = push_energy_info(subzonedir);
          }
  }
  return ind;
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

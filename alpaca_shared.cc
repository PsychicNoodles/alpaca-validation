#include "alpaca_shared.hh"

#include "alpaca_no2.hh"
#include "alpaca_fn_disabler.hh"

uint64_t offset;

uint64_t func_address; //the address of the target function

fstream return_file;
fstream write_file;

typedef int (*main_fn_t)(int, char**, char**);
main_fn_t og_main;

static int wrapped_main(int argc, char** argv, char** env) {
        cerr << "Entered main wrapper\n";
        
        //storing the func_name searched for as the last argument
        string func_name = argv[argc-2];  
        argv[argc-2] = NULL;
        cerr << "func_name: " << func_name << "\n";

        func_address = find_address("/proc/self/exe", func_name);

        for(int i=0; i<argc; i++) {
                cerr << i << ": " << argv[i] << "\n";
        }

        
        if (strcmp(argv[argc-1], "analyze") == 0) {
                return_file.open("return-logger", fstream::out | fstream::trunc | fstream::binary);
                write_file.open("write-logger", fstream::out | fstream::trunc | fstream::binary);
     
                //
                //set up for the SIGTRAP signal handler
                
                struct sigaction sa = {
                        .sa_sigaction = trap_handler,
                        .sa_flags = SA_SIGINFO
                };
                sigaction(SIGTRAP, &sa, NULL);
        
                //     asm("int $3"); 
                single_step(func_address);

                

        } else if (strcmp(argv[argc-1], "disable") == 0) {
                return_file.open("return-logger", fstream::in | fstream::binary);
                write_file.open("write-logger", fstream::in | fstream::binary);
                
                read_writes();
                read_returns();
                
        } else {
                cerr << "Unknown mode!\n";
                exit(2);
        }
         
        argc -= 2;

        map<string, uint64_t> start_readings = measure_energy();
        og_main(argc, argv, env);
        map<string, uint64_t> end_readings = measure_energy();

        cerr << "Energy consumption (%lu):" << end_readings.size() << endl;
        for(auto &ent : end_readings) {
                cerr << ent.first << ": " << ent.second - start_readings.at(ent.first) << endl;
        }

        return_file.close();
        write_file.close();

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

string file_readline(string path) {
        ifstream in(path);
        string str;
        in >> str;
        return str;
}

vector<string> find_in_dir(string dir, string substr) {
        vector<string> res;
        DIR* dirp = opendir(dir.c_str());
        struct dirent* dp;
        while((dp = readdir(dirp)) != NULL) {
                string path = string(dp->d_name);
                if(path.find(substr) != string::npos) {
                        res.push_back(path);
                }
        }
        closedir(dirp);
        return res;
}

void push_energy_info(map<string, uint64_t>* readings, string dir) {
        string name = file_readline(dir + ENERGY_NAME);
        uint64_t energy;
        istringstream(file_readline(dir + ENERGY_FILE)) >> energy;
        readings->insert(make_pair(name, energy));
}

map<string, uint64_t> measure_energy() {
        map<string, uint64_t> readings;
        vector<string> powerzones = find_in_dir(ENERGY_ROOT, "intel-rapl:");
        for(auto &zone : powerzones) {
                string zonedir = string(ENERGY_ROOT) + "/" + zone + "/";
                push_energy_info(&readings, zonedir);
                vector<string> subzones = find_in_dir(zonedir, zone);
                for(auto &sub : subzones) {
                        // path join in C++
                        push_energy_info(&readings, zonedir + sub + "/");
                }
        }
        return readings;
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

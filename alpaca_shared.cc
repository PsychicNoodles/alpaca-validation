#include "alpaca_shared.hh"

uint64_t offset;

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

ReturnMode parse_argv(int argc, char** argv) {
        string mode = string(argv[argc-2]);
        if(mode == "float") return FLOAT;
        else if(mode == "struct") return LARGE;
        else if(mode == "int") return INT;
        else {
                fprintf(stderr, "Invalid return type mode %s\n", mode.c_str());
                exit(3);
        }
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

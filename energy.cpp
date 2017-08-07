#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <cstdint>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <sstream>

#include <dirent.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#define ENERGY_ROOT "/sys/class/powercap/intel-rapl/"
#define ENERGY_PREFIX "intel-rapl"
#define ENERGY_NAME "name"
#define ENERGY_FILE "energy_uj"

#if defined(NDEBUG)
#define DEBUG(x)
#else
#define DEBUG(x) do { clog << x << "\n"; } while(0)
#endif


using namespace std;

vector<map<string, uint64_t>> measurements;
char* func;

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
  DEBUG("Pushing energy info for " << dir);
  string name = file_readline(dir + ENERGY_NAME);
  uint64_t energy;
  istringstream(file_readline(dir + ENERGY_FILE)) >> energy;
  DEBUG("Reading for " << name << ": " << energy);
  readings->insert(make_pair(name, energy));
}

void measure_energy() {
  DEBUG("Measuring energy");
  map<string, uint64_t> readings;
  vector<string> powerzones = find_in_dir(ENERGY_ROOT, "intel-rapl:");
  DEBUG("Found " << powerzones.size() << " zones");
  for(auto &zone : powerzones) {
    DEBUG("Trying zone " << zone);
    string zonedir = string(ENERGY_ROOT) + "/" + zone + "/";
    push_energy_info(&readings, zonedir);
    vector<string> subzones = find_in_dir(zonedir, zone);
    DEBUG("Found " << subzones.size() << " subzones");
    for(auto &sub : subzones) {
      DEBUG("Trying subzone " << sub);
      push_energy_info(&readings, zonedir + sub + "/");
    }
  }
  measurements.push_back(readings);
  DEBUG("Finished measuring energy");
}

void sig_measure_handler(int signal) {
  if(signal != SIGUSR1) {
    cerr << "Measurement handler caught the wrong signal: " << sys_siglist[signal] << "!\n";
    exit(3);
  }
  DEBUG("Measuring energy");
  measure_energy();
}

void sig_stop_handler(int signal) {
  if(signal != SIGUSR2) {
    cerr << "Stop handler caught the wrong signal: " << sys_siglist[signal] << "!\n";
    exit(3);
  }

  DEBUG("Stopping");
  cout << "Energy measurements for function: " << func << "\n";
    
  for (int i = measurements.size()-1; i > 0; i--) {
    cout << "Comparing reading " << i << " and " << i - 1 << "\n";
      
    uint64_t energy;
    string zone;
    for (const auto &pair: measurements.at(i)) {
      zone = pair.first;   
      energy = pair.second - measurements.at(i-1).at(zone);
        
      cout << "Zone " << zone << ": " << energy << "\n";
    }
  }

  exit(0);
}

int main(int argc, char** argv){
  int num_args = argc - 1;
  if (num_args < 2) {
    cerr << "Incorrect usage!\n";
    exit(2);
  }

  DEBUG("Started energy utility");
  
  const char* prog_path = argv[1];
  func = argv[2];

  char* sub_argv[argc];
  for(int i = 1; i < argc; i++) {
    sub_argv[i - 1] = (char*) malloc(strlen(argv[i]) + 1);
    strcpy(sub_argv[i - 1], argv[i]);
  }
  sub_argv[argc - 1] = NULL;

  DEBUG("Test program is " << prog_path);
  DEBUG("Test function is " << func);
  
  //setting up the environment
  string env_func = "ALPACA_FUNC=";
  env_func += func;
  env_func += "_func";
  char* env[5];
  env[0] = (char*) "LD_PRELOAD=./alpaca.so:libelf++.so:libudis86.so";
  env[2] = (char*) env_func.c_str();
  env[4] = NULL;

  pid_t pid;
  if((pid = fork()) == 0) { //child parent
    pid_t parent_pid = getppid();

    string env_ppid = "ALPACA_PPID=";
    env_ppid += to_string(parent_pid);
    env[3] = (char*) env_ppid.c_str();
      
    pid_t alpaca_pid;
    if ((alpaca_pid = fork()) == 0) {
      DEBUG("In analyzer fork, pid " << getpid());
      //run analyzer

      //setting up the environment mode
      env[1] = (char*) "ALPACA_MODE=a";

      for(int i = 0; i < 5; i++) {
        DEBUG("Analyzer env[" << i << "]: " << env[i]);
      }

      for(int i = 0; i < argc; i++) {
        DEBUG("Analyzer argv[" << i << "]: " << (sub_argv[i] == NULL ? "NULL" : sub_argv[i]));
      }

      DEBUG("Analyzer executing");
      if (execvpe(prog_path, sub_argv, env) == -1) {
        DEBUG("Analyzer exec failed" << strerror(errno));
      }
      
    } else if (alpaca_pid == -1) {
      DEBUG("Forking failed");
      exit(3);
    } else { //run disabler
      DEBUG("In disabler fork, waiting for " << alpaca_pid);
      
      int status;
      waitpid(alpaca_pid, &status, 0);
      DEBUG("Disabler finished waiting, status was " << status);

      env[1] = (char*) "ALPACA_MODE=d";
     
      for(int i = 0; i < 4; i++) {
        DEBUG("Disabler env[" << i << "]: " << env[i]);
      }

      for(int i = 0; i < argc; i++) {
        DEBUG("Disabler argv[" << i << "]: " << (sub_argv[i] == NULL ? "NULL" : sub_argv[i]));
      }

      DEBUG("Disabler executing");

      if (execvpe(prog_path, sub_argv, env) == -1) {
        DEBUG("Disabler exec failed" << strerror(errno));
      }
    }
  } else if (pid == -1) {
    DEBUG("Forking failed");
    exit(3);
  } else { //parent process
    DEBUG("In parent process");
    struct sigaction measure_sigaction, stop_sigaction;
    
    memset(&measure_sigaction, 0, sizeof(struct sigaction));
    measure_sigaction.sa_handler = sig_measure_handler;
    sigemptyset(&measure_sigaction.sa_mask);

    memset(&stop_sigaction, 0, sizeof(struct sigaction));
    stop_sigaction.sa_handler = sig_stop_handler;
    sigemptyset(&stop_sigaction.sa_mask);

    DEBUG("Setting up signal handlers");
    sigaction(SIGUSR1, &measure_sigaction, NULL);
    sigaction(SIGUSR2, &stop_sigaction, NULL);
    DEBUG("Setup finished");

    while(1){}
  }
}

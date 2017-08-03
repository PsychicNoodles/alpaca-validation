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
  string name = file_readline(dir + ENERGY_NAME);
  uint64_t energy;
  istringstream(file_readline(dir + ENERGY_FILE)) >> energy;
  readings->insert(make_pair(name, energy));
}

void measure_energy() {
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
  measurements.push_back(readings);
}

void sig_measure_handler(int signal) {
  if(signal != SIGUSR1) {
    cerr << "Measurement handler caught the wrong signal: " << signal << "!\n";
    exit(3);
  }
  DEBUG("Measuring energy");
  measure_energy();
}

void sig_stop_handler(int signal) {
  if(signal != SIGUSR1) {
    cerr << "Stop handler caught the wrong signal: " << signal << "!\n";
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

  DEBUG("Test program is " << prog_path);
  DEBUG("Test function is " << func);
  
  pid_t pid;
  if((pid = fork()) == 0) { //child parent
    pid_t parent_pid = getppid();
    
    pid_t alpaca_pid;
    if ((alpaca_pid = fork()) == 0) {
      DEBUG("In analyzer fork, pid " << getpid());
      //run analyzer

      //setting up the environment
      string env_func = "ALPACA_FUNC=";
      env_func += func;
      env_func += "_func";
      string env_ppid = "ALPACA_PPID=";
      env_ppid += to_string(parent_pid);
      char* env[4];
      env[0] = (char*) "LD_PRELOAD=./alpaca.so:libelf++.so:libudis86.so";
      env[1] = (char*) "ALPACA_MODE=a";
      env[2] = (char*) env_func.c_str();
      env[3] = (char*) env_ppid.c_str();

      for(int i = 0; i < 4; i++) {
        DEBUG("Analyzer: env[" << i << "]: " << env[i]);
      }

      DEBUG("Analyzer executing");
      execve(prog_path, &argv[1], env);
    } else { //run disabler
      DEBUG("In disabler fork, waiting for " << alpaca_pid);
      int status;
      waitpid(alpaca_pid, &status, 0);
      DEBUG("Disabler finished waiting, status was " << status);

      string env_func = "ALPACA_FUNC=";
      env_func += func;
      env_func += "_func";
      string env_ppid = "ALPACA_PPID=";
      env_ppid += to_string(parent_pid);
      char* env[4];
      env[0] = (char*) "LD_PRELOAD=./alpaca.so:libelf++.so:libudis86.so";
      env[1] = (char*) "ALPACA_MODE=d";
      env[2] = (char*) env_func.c_str();
      env[3] = (char*) env_ppid.c_str();

      for(int i = 0; i < 4; i++) {
        DEBUG("Disabler env[" << i << "]: " << env[i]);
      }

      DEBUG("Disabler executing");

      execve(prog_path, &argv[1], env);
    }
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
  }
}

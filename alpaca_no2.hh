#include <cstdint>
#include <signal.h>

void trap_handler(int signal, siginfo_t* info, void* cont);

#include <cstdint>
#include <signal.h>

void single_step(uint64_t func_address);
void trap_handler(int signal, siginfo_t* info, void* cont);

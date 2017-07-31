void read_writes();
void read_returns();
void read_syscalls();
void read_ret_addrs();
void setup_disabler_jump();
void check_trap_handler(int signal, siginfo_t* info, void* cont);
void trap_register_handler(int signal, siginfo_t* info, void* cont);

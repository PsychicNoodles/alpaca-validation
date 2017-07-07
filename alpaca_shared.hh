#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#ifndef ALPACA_SHARED
#define ALPACA_SHARED

#include "elf++.hh"
#include "interpose.hh" //interposing exit functions

#include <fcntl.h>
#include <link.h>
#include <unistd.h>

#include <sys/types.h>
#include <dirent.h>

#include <sstream>
#include <string>
#include <fstream>
#include <iostream>

#include <cstdlib>

#define MAX_POWERZONES 128
#define MAX_ENERGY_READING 128
#define NUM_ENERGY_READINGS 128
#define ENERGY_ROOT "/sys/class/powercap/intel-rapl/"
#define ENERGY_NAME "name"
#define ENERGY_FILE "energy_uj"
#define ENERGY_LINE_CAPACITY 1024

#define MAX_RETURNS 100000
#define MAX_WRITES 100000000
#define MAX_SYSCALLS 10000000

using namespace std;

//debug macro
#if defined(NDEBUG)
#define DEBUG(x)
#define DEBUG_CRITICAL(x)
#elif defined(MINDEBUG)
#define DEBUG(x)
#define DEBUG_CRITICAL(x) do { clog << x << "\n"; } while(0)
#else
#define DEBUG(x) do { clog << x << "\n"; } while(0)
#define DEBUG_CRITICAL(x) do { clog << x << "\n"; } while(0)
#endif

typedef struct {
        string name;
        int args;
} syscall_t;

static syscall_t syscalls[283] = {
        {"read", 3},
        {"write", 3},
        {"open", 3},
        {"close", 1},
        {"stat", 2},
        {"fstat", 2},
        {"lstat", 2},
        {"poll", 3},
        {"lseek", 3},
        {"mmap", 6},
        {"mprotect", 3},
        {"munmap", 2},
        {"brk", 1},
        {"rt_sigaction", 4},
        {"rt_sigprocmask", 4},
        {"rt_sigreturn", 3},
        {"ioctl", 4},
        {"pread64", 4},
        {"pwrite64", 3},
        {"readv", 3},
        {"writev", 2},
        {"access", 1},
        {"pipe", 5},
        {"select", 1},
        {"sched_yield", 3},
        {"mremap", 3},
        {"msync", 3},
        {"mincore", 3},
        {"madvise", 3},
        {"shmget", 3},
        {"shmat", 1},
        {"shmctl", 2},
        {"dup", 2},
        {"dup2", 2},
        {"pause", 1},
        {"nanosleep", 3},
        {"getitimer", 4},
        {"alarm", 3},
        {"setitimer", 3},
        {"getpid", 3},
        {"sendfile", 6},
        {"socket", 6},
        {"connect", 3},
        {"accept", 3},
        {"sendto", 2},
        {"recvfrom", 3},
        {"sendmsg", 2},
        {"recvmsg", 3},
        {"shutdown", 3},
        {"bind", 4},
        {"listen", 5},
        {"getsockname", 5},
        {"getpeername", 5},
        {"socketpair", 3},
        {"setsockopt", 1},
        {"getsockopt", 4},
        {"clone", 2},
        {"fork", 1},
        {"vfork", 3},
        {"execve", 3},
        {"exit", 4},
        {"wait4", 1},
        {"kill", 2},
        {"uname", 4},
        {"semget", 5},
        {"semop", 3},
        {"semctl", 3},
        {"shmdt", 2},
        {"msgget", 1},
        {"msgsnd", 1},
        {"msgrcv", 2},
        {"msgctl", 2},
        {"fcntl", 3},
        {"flock", 2},
        {"fsync", 1},
        {"fdatasync", 1},
        {"truncate", 2},
        {"ftruncate", 2},
        {"getdents", 1},
        {"getcwd", 2},
        {"chdir", 2},
        {"fchdir", 1},
        {"rename", 2},
        {"mkdir", 3},
        {"rmdir", 2},
        {"creat", 2},
        {"link", 3},
        {"unlink", 3},
        {"symlink", 3},
        {"readlink", 1},
        {"chmod", 2},
        {"fchmod", 2},
        {"chown", 2},
        {"fchown", 1},
        {"lchown", 1},
        {"umask", 4},
        {"gettimeofday", 3},
        {"getrlimit", 1},
        {"getrusage", 1},
        {"sysinfo", 2},
        {"times", 2},
        {"ptrace", 2},
        {"getuid", 2},
        {"syslog", 2},
        {"getgid", 3},
        {"setuid", 3},
        {"setgid", 3},
        {"geteuid", 3},
        {"getegid", 1},
        {"setpgid", 1},
        {"getppid", 1},
        {"getpgrp", 1},
        {"setsid", 2},
        {"setreuid", 2},
        {"setregid", 2},
        {"getgroups", 4},
        {"setgroups", 3},
        {"setresuid", 2},
        {"getresuid", 2},
        {"setresgid", 2},
        {"getresgid", 3},
        {"getpgid", 1},
        {"setfsuid", 1},
        {"setfsgid", 2},
        {"getsid", 2},
        {"capget", 2},
        {"capset", 3},
        {"rt_sigpending", 2},
        {"rt_sigtimedwait", 3},
        {"rt_sigqueueinfo", 2},
        {"rt_sigsuspend", 2},
        {"sigaltstack", 3},
        {"utime", 1},
        {"mknod", 1},
        {"uselib", 1},
        {"personality", 2},
        {"ustat", 2},
        {"statfs", 2},
        {"fstatfs", 1},
        {"sysfs", 3},
        {"getpriority", 2},
        {"setpriority", 1},
        {"sched_setparam", 5},
        {"sched_getparam", 3},
        {"sched_setscheduler", 1},
        {"sched_getscheduler", 2},
        {"sched_get_priority_max", 1},
        {"sched_get_priority_min", 1},
        {"sched_rr_get_interval", 2},
        {"mlock", 5},
        {"munlock", 2},
        {"mlockall", 2},
        {"munlockall", 1},
        {"vhangup", 4},
        {"modify_ldt", 2},
        {"pivot_root", 2},
        {"_sysctl", 1},
        {"prctl", 3},
        {"arch_prctl", 3},
        {"adjtimex", 2},
        {"setrlimit", 4},
        {"chroot", 3},
        {"sync", 5},
        {"acct", 5},
        {"settimeofday", 5},
        {"mount", 4},
        {"umount2", 4},
        {"swapon", 4},
        {"swapoff", 3},
        {"reboot", 3},
        {"sethostname", 3},
        {"setdomainname", 2},
        {"iopl", 2},
        {"ioperm", 2},
        {"create_module", 2},
        {"init_module", 1},
        {"delete_module", 6},
        {"get_kernel_syms", 3},
        {"query_module", 3},
        {"quotactl", 1},
        {"nfsservctl", 2},
        {"getpmsg", 1},
        {"putpmsg", 5},
        {"afs_syscall", 3},
        {"tuxcall", 3},
        {"security", 1},
        {"gettid", 3},
        {"readahead", 1},
        {"setxattr", 5},
        {"lsetxattr", 3},
        {"fsetxattr", 1},
        {"getxattr", 4},
        {"lgetxattr", 4},
        {"fgetxattr", 3},
        {"listxattr", 4},
        {"llistxattr", 2},
        {"flistxattr", 1},
        {"removexattr", 1},
        {"lremovexattr", 2},
        {"fremovexattr", 2},
        {"tkill", 2},
        {"time", 4},
        {"futex", 1},
        {"sched_setaffinity", 4},
        {"sched_getaffinity", 4},
        {"set_thread_area", 3},
        {"io_setup", 2},
        {"io_destroy", 6},
        {"io_getevents", 3},
        {"io_submit", 5},
        {"io_cancel", 4},
        {"get_thread_area", 1},
        {"lookup_dcookie", 5},
        {"epoll_create", 5},
        {"epoll_ctl_old", 2},
        {"epoll_wait_old", 3},
        {"remap_file_pages", 4},
        {"getdents64", 5},
        {"set_tid_address", 5},
        {"restart_syscall", 4},
        {"semtimedop", 5},
        {"fadvise64", 3},
        {"timer_create", 2},
        {"timer_settime", 3},
        {"timer_gettime", 2},
        {"timer_getoverrun", 4},
        {"timer_delete", 4},
        {"clock_settime", 3},
        {"clock_gettime", 4},
        {"clock_getres", 5},
        {"clock_nanosleep", 3},
        {"exit_group", 4},
        {"epoll_wait", 3},
        {"epoll_ctl", 4},
        {"tgkill", 5},
        {"utimes", 3},
        {"vserver", 4},
        {"mbind", 3},
        {"set_mempolicy", 3},
        {"get_mempolicy", 6},
        {"mq_open", 5},
        {"mq_unlink", 1},
        {"mq_timedsend", 2},
        {"mq_timedreceive", 3},
        {"mq_notify", 6},
        {"mq_getsetattr", 4},
        {"kexec_load", 4},
        {"waitid", 4},
        {"add_key", 6},
        {"request_key", 4},
        {"keyctl", 6},
        {"ioprio_set", 3},
        {"ioprio_get", 2},
        {"inotify_init", 1},
        {"inotify_add_watch", 4},
        {"inotify_rm_watch", 4},
        {"migrate_pages", 2},
        {"openat", 4},
        {"mkdirat", 4},
        {"mknodat", 2},
        {"fchownat", 1},
        {"futimesat", 3},
        {"newfstatat", 2},
        {"unlinkat", 1},
        {"renameat", 5},
        {"linkat", 5},
        {"symlinkat", 4},
        {"readlinkat", 5},
        {"fchmodat", 5},
        {"faccessat", 2},
        {"pselect6", 5},
        {"ppoll", 4},
        {"unshare", 5},
        {"set_robust_list", 3},
        {"get_robust_list", 2},
        {"splice", 1},
        {"tee", 4},
        {"sync_file_range", 2},
        {"vmsplice", 3},
        {"move_pages", 6},
        {"utimensat", 6},
        {"epoll_pwait", 5},
        {"signalfd", 3}
};

typedef struct {
        char* zone;
        uint64_t energy;
} energy_reading_t;

extern uint64_t func_address; //the address of the target function

extern fstream return_file;
extern fstream write_file;
extern fstream sys_file;

/**
 * Locates the address of the target function
 * file_path: the path to the binary file
 * func_name: the name of the target function
 */
uint64_t find_address(const char* file_path, string func_name);

int measure_energy(energy_reading_t* readings, int max);

char* int_to_hex(uint64_t i);

#endif

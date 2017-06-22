#include "alpaca_shared.hh"

#include "elf++.hh"
#include "x86jump.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <link.h>
#include <unistd.h>

#include <fstream>
#include <string>
#include <iostream>
#include <queue>
#include <array>

#define PAGE_SIZE 4096

using namespace std;


typedef struct {
  uint8_t flag;
  uint64_t rax;
  uint64_t rdx;
  uint32_t xmm0[4];
  uint32_t xmm1[4]; 
} ret_t; 


queue<ret_t> returns;
queue<syscall_t> sys_pre;
queue<syscall_t> sys_post;
queue<uint64_t> syspre_count_queue;
queue<uint64_t> syspost_count_queue; 


queue<uint64_t> write_count_queue; 
queue<uint64_t> writes; //returning from write-logger

void mimic_writes_disabler(uint64_t write_count);

void disabled_fn() {
  fprintf(stderr, "disabled_fn\n");

  uint64_t sys_pre_count = syspre_count_queue.front();
  syspre_count_queue.pop();
  if(sys_pre_count !=0) mimic_sys_pre(sys_pre_count);

  uint64_t wc = write_count_queue.front();
  write_count_queue.pop();
  if (wc != 0) mimic_writes_disabler(wc);

  
  uint64_t sys_post_count = syspost_count_queue.front();
  syspost_count_queue.pop();
  if(sys_post_count !=0) mimic_sys_pre(sys_pre_count);

  ret_t curr_return = returns.front();
  returns.pop();

  fprintf(stderr, "flag: %d\n", curr_return.flag);

  if(curr_return.flag & 0b11110000) {
    fprintf(stderr, "only rax and rdx supported (%d)\n", curr_return.flag);
    exit(5);
  }

  if(curr_return.flag & 0b00001000) fprintf(stderr, "xmm1: %lf\n", *((double*) curr_return.xmm1));
  if(curr_return.flag & 0b00000100) fprintf(stderr, "xmm0: %lf\n", *((double*) curr_return.xmm0));
        
  if(curr_return.flag & 0b00000010) fprintf(stderr, "rdx: %lu\n", curr_return.rdx);
  if(curr_return.flag & 0b00000001) fprintf(stderr, "rax: %lu\n", curr_return.rax);
 
  if(curr_return.flag & 0b00001000) asm("mov %0, %%xmm1" : : "r"(curr_return.xmm1) : );
  if(curr_return.flag & 0b00000100) asm("mov %0, %%xmm0" : : "r"(curr_return.xmm0) : );
        
  if(curr_return.flag & 0b00000010) asm("" : : "d"(curr_return.rdx) : );
  //other registers and if statements (comparison) use rax to store their values so it should come last 
  if(curr_return.flag & 0b00000001) asm("" : : "a"(curr_return.rax) : );
}


void mimic_sys_pre(uint64_t sys_pre_count){
 fprintf(stderr, "mimicing sys_pre with count %lu\n",sys_pre_count);
 for(int i = 0; i < sys_pre_count; i++){
   uint64_t sys_num = sys_pre.front();
   
   


 }


}

void mimic_sys_post(uint64_t sys_post_count){



}

void mimic_writes_disabler(uint64_t write_count) {
  fprintf(stderr, "mimicing writes with count %lu\n", write_count);
  for(int i = 0; i < write_count; i++){
    uint64_t* memory_dest = (uint64_t*) writes.front();
    writes.pop();
    uint64_t val = writes.front();
    writes.pop();

    *memory_dest = val;
    fprintf(stderr, "wrote %lu into %p\n", val, (void*)memory_dest);
  }
}



void read_sys_pre(){
   uint64_t buffer; 
   while(sys_file_pre.read((char*) &buffer, sizeof(uint64_t))){
    sys_file_pre.read((char*) &buffer, sizeof(uint64_t)); 
    sys_pre.push(buffer);
    fprintf(stderr, "logged sys_pre in disabler: %p\n", (void*)buffer);
  }
}



void read_sys_post(){
   uint64_t buffer; 
   while(sys_file_post.read((char*) &buffer, sizeof(uint64_t))){
    sys_file_post.read((char*) &buffer, sizeof(uint64_t)); 
    sys_post.push(buffer);
    fprintf(stderr, "logged sys_post in disabler: %p\n", (void*)buffer);
  }
}


//first log memory address
//second log value at the mem address (both uint64_t)
void read_writes() {
  while (!write_file.eof()) {
    uint64_t buffer; 
    write_file.read((char*) &buffer, sizeof(uint64_t)); 
    writes.push(buffer);
    fprintf(stderr, "logged writes in disabler: %p\n", (void*)buffer);
  }
}

//first log number of writes
//second log return struct

void read_returns() {
  while(!return_file.eof()) {

    uint64_t sys_pre_count;
    return_file.read((char*) &sys_pre_count, sizeof(uint64_t));
    syspre_count_queue.push(&sys_pre_count);
    
    uint64_t wc;
    return_file.read((char*) &wc, sizeof(uint64_t));
    write_count_queue.push(wc);

    
    uint64_t sys_post_count;
    return_file.read((char*) &sys_post_count, sizeof(uint64_t));
    syspost_count_queue.push(&sys_post_count);
    

    ret_t return_struct; 
    return_file.read((char*) &return_struct.flag, 1);

    if(return_struct.flag & 0b00000001) return_file.read((char*) &return_struct.rax, 8);
    if(return_struct.flag & 0b00000010) return_file.read((char*) &return_struct.rdx, 8);

    if(return_struct.flag & 0b00000100) {
      for (int i = 0; i < 4; i ++) return_file.read((char*) &return_struct.xmm0[i], 4);
      fprintf(stderr, "logging value: %lf\n", *((double*)return_struct.xmm0));
    }

    if(return_struct.flag & 0b00001000) {
      for (int i = 0; i < 4; i ++) return_file.read((char*) &return_struct.xmm1[i], 4);
    }

    returns.push(return_struct);
  }
        
  uint64_t page_start = func_address & ~(PAGE_SIZE-1) ;

  //making the page writable, readable and executable
  if (mprotect((void*) page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
    fprintf(stderr, "%s\n", strerror(errno));
    exit(2); 
  }

  new((void*)func_address)X86Jump((void*)disabled_fn);

  //switch back to old permissions! 
}

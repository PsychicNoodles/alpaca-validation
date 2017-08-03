#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

typedef struct {
  int a;
} int_struct_t;

typedef struct {
  double a;
} double_struct_t;

typedef struct {
  int a;
  int b;
} two_int_t;

typedef struct {
  float a;
  float b;
} two_float_t;


typedef struct {
  int a;
  int b;
  double c;
} mixed_t;

typedef struct {
  int a;
  int b;
  int c;
  int d;
  int e;
  int f;
  int g;
  int h;
} eight_int_t;

typedef struct {
  bool a;
  short b;
  long d;
  double g;
  long long e;
  float f;
  int c;
} everything_t;

typedef struct {
  int a;
  float b;
  char* c;
} pointer_t;

typedef struct {
  double a;
  double b;
  double c;
} triple_double_t;

typedef struct {
  long long a;
  long long b;
  long long c;
  long long d;
  long long e;
  long long f;
  long long g;
  long long h;
  long long i;
  long long j;
  long long k;
  long long l;
  long long m;
  long long n;
  long long o;
  long long p;
} sixteen_ll_t;

bool bool_func() {
  bool ret = true;
  return ret;
}

short short_func() {
  short ret = 2;
  return ret;
}

int int_func() {
  int ret = 3;
  return ret;
}

long long_func() {
  long ret = 4;
  return ret;
}

long long long_long_func() {
  long long ret = 5;
  return ret;
}

float float_func() {
  float ret = -12345.6;
  return ret;
}

float param_float_func(float a) {
  float ret = 6.0 + a;
  return ret;
}

double double_func() {
  double ret = 7.0;
  return ret;
}

int_struct_t int_struct_func() {
  int_struct_t ret;
  ret.a = 8;
  return ret;
}

double_struct_t double_struct_func() {
  double_struct_t ret;
  ret.a = 9.0;
  return ret;
}

two_int_t two_int_func() {
  two_int_t ret;
  ret.a = 10;
  ret.b = 11;
  return ret;
}

two_float_t two_float_func() {
  two_float_t ret;
  ret.a = 12.0;
  ret.b = 13.0;
  return ret;
}

mixed_t mixed_func() {
  mixed_t ret;
  ret.a = 14;
  ret.b = 15;
  ret.c = 16.0;
  return ret;
}

eight_int_t eight_int_func() {
  eight_int_t ret;
  ret.a = 17;
  ret.b = 18;
  ret.c = 19;
  ret.d = 20;
  ret.e = 21;
  ret.f = 22;
  ret.g = 23;
  ret.h = 24;
  return ret;
}

everything_t everything_func() {
  everything_t ret;
  ret.a = true;
  ret.b = 24;
  ret.c = 25;
  ret.d = 26;
  ret.e = 27;
  ret.f = 28.0;
  ret.g = 29.0;
  return ret;
}

pointer_t pointer_func() {
  pointer_t ret;
  ret.a = 30;
  ret.b = 31.0;
  ret.c = (char*) malloc(sizeof(char) * 9);
  ret.c[0] = 't';
  ret.c[1] = 'e';
  ret.c[2] = 's';
  ret.c[3] = 't';
  ret.c[4] = 't';
  ret.c[5] = 'e';
  ret.c[6] = 's';
  ret.c[7] = 't';
  ret.c[8] = '\0';
  
  return ret;
}

#define NUM_MALLOCS 100
void malloc_free_func() {
  char* a[NUM_MALLOCS];
  //  printf("malloced array of size %d\n", NUM_MALLOCS);
  for (int i = 0; i < NUM_MALLOCS; i++) {
    a[i] = (char*)malloc(sizeof(char)*(i*3));
    //  printf("malloced item at %d of size %d\n", i, i*3);
  }
  //printf("finished mallocing\n");

  
  //for(int i = 0; i < NUM_MALLOCS; i++)
  // printf("malloced: %p\n", a[i]);

  for (int i = 0; i < NUM_MALLOCS; i++) {
   free(a[i]);
   // printf("freed item at %d\n", i);
  }
  //printf("returning\n");
  
}

triple_double_t triple_double_func() {
  triple_double_t ret;
  ret.a = 32.0;
  ret.b = 33.0;
  ret.c = 34.0;
  return ret;
}

void mem_cpy_func(char arr1[], char arr2[], int size) {
  memcpy(arr1, arr2, size);
  return;
}

sixteen_ll_t sixteen_ll_func() {
  sixteen_ll_t ret;
  ret.a = 123456;
  ret.b = 234567;
  ret.c = 345678;
  ret.d = 456789;
  ret.e = 5678910;
  ret.f = 67891011;
  ret.g = 789101112;
  ret.h = 8910111213;
  ret.i = 91011121314;
  ret.j = 101112131415;
  ret.k = 111213141516;
  ret.l = 121314151617;
  ret.m = 131415161718;
  ret.n = 141516171819;
  ret.o = 151617181920;
  ret.p = 161718192021;
  return ret;
}


int global_a;
double global_b;
char global_c[9];

void global_write_func() {
  global_a = 1;
  global_b = 2.0;
  strncpy(global_c, "testtest", 9);
}

void local_func(int* ptr) {
  *ptr = 2;
}

int* mmap_func() {
  int* ptr = (int*) mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  *ptr = 1234;
  return ptr;
}

#define MAX_PRINTFS 100
void printf_func() {
  for(int i = 0; i < MAX_PRINTFS; i++) printf("printf %d\n", i);
}

bool cmp(char* test1, char* test2) {
  return strcmp(test1, test2) == 0;
}

int main(int argc, char** argv) {
  if(argc < 2) {
    fprintf(stderr, "must include testing function\n");
    exit(2);
  }
        
  if(cmp(argv[1], "bool")) printf("%d\n", bool_func());
  if(cmp(argv[1], "short")) printf("%d\n", short_func());
  if(cmp(argv[1], "int")) printf("%d\n", int_func());
  if(cmp(argv[1], "long")) printf("%ld\n", long_func());
  if(cmp(argv[1], "long_long")) printf("%lld\n", long_long_func());
  if(cmp(argv[1], "float")) printf("%.1f\n", float_func());
  if(cmp(argv[1], "double")) printf("%.1lf\n", double_func());
  if(cmp(argv[1], "int_struct")) {
    int_struct_t ret = int_struct_func();
    printf("%d\n", ret.a);
  }
  if(cmp(argv[1], "double_struct")) {
    double_struct_t ret = double_struct_func();
    printf("%.1lf\n", ret.a);
  }
  if(cmp(argv[1], "two_int")) {
    two_int_t ret = two_int_func();
    printf("%d %d\n", ret.a, ret.b);
  }
  if(cmp(argv[1], "two_float")) {
    two_float_t ret = two_float_func();
    printf("%.1f %.1f\n", ret.a, ret.b);
  }
  if(cmp(argv[1], "mixed")) {
    mixed_t ret = mixed_func();
    printf("%d %d %.1lf\n", ret.a, ret.b, ret.c);
  }
  if(cmp(argv[1], "mem_cpy")) {
    char* arr1 = "abcdefghijklmnopqrstuvwxyz";
    char arr2[28];
    mem_cpy_func(arr2, arr1, 28);
    printf("%s\n", arr2);
  }
  if(cmp(argv[1], "eight_int")) {
    eight_int_t ret = eight_int_func();
    printf("%d %d %d %d %d %d %d %d\n", ret.a, ret.b, ret.c, ret.d, ret.e, ret.f, ret.g, ret.h);
  }
  if(cmp(argv[1], "everything")) {
    everything_t ret = everything_func();
    printf("%d %d %d %ld %lld %.1f %.1lf\n", ret.a, ret.b, ret.c, ret.d, ret.e, ret.f, ret.g);
  }
  if(cmp(argv[1], "pointer")) {
    pointer_t ret = pointer_func();
    printf("%d %.1lf %s\n", ret.a, ret.b, ret.c);
  }
  if(cmp(argv[1], "malloc_free")) {
    malloc_free_func();
    printf("0\n");
  }
  if(cmp(argv[1], "triple_double")) {
    triple_double_t ret = triple_double_func();
    printf("%.1lf %.1lf %.1lf\n", ret.a, ret.b, ret.c);
  }
  if(cmp(argv[1], "global_write")) {
    global_a = 0;
    global_b = 0;
    global_write_func();
    printf("%d %.1lf %s\n", global_a, global_b, global_c);
  }
  if(cmp(argv[1], "param_float")) {
    float a = 3.3;
    float b = param_float_func(a);
    printf("%.1lf\n", b);
  }
  if(cmp(argv[1], "local")) {
    int ret = 1;
    local_func(&ret);
    printf("%d\n", ret);
  }
  if(cmp(argv[1], "mmap")) {
    int* ret = mmap_func();
    printf("%d\n", *ret);
  }
  if(cmp(argv[1], "sixteen_ll")) {
          sixteen_ll_t ret = sixteen_ll_func();
          printf("%lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld\n", ret.a, ret.b, ret.c, ret.d, ret.e, ret.f, ret.g, ret.h, ret.i, ret.j, ret.k, ret.l, ret.m, ret.n, ret.o, ret.p);
  }
  if(cmp(argv[1], "printf")) {
          printf_func();
  }
}

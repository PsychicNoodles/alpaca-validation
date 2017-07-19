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
  int c;
  long d;
  long long e;
  float f;
  double g;
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
  float ret = 6.0;
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
  ret.c[0] = 'e';
  ret.c[0] = 's';
  ret.c[0] = 't';
  ret.c[0] = 't';
  ret.c[0] = 'e';
  ret.c[0] = 's';
  ret.c[0] = 't';
  ret.c[0] = '\0';
  
  return ret;
}

void malloc_free_func() {
  char* a[500]; 
  for (int i = 0; i < 500; i++) 
    a[i] = (char*)malloc(sizeof(char)*(i*3));

  for(int i = 0; i < 500; i++)
     printf("malloced: %p\n", a[i]);

  //for (int i = 0; i < 500; i++)
          //free(a[i]);
}

triple_double_t triple_double_func() {
  triple_double_t ret;
  ret.a = 32.0;
  ret.b = 33.0;
  ret.c = 34.0;
  return ret;
}

/*__int128 really_long_func() {
  __int128 ret = 35;
  return ret;
  }*/

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
    //printf("0\n");
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
  //how print
  //if(cmp(argv[1], "reallylong")) printf("really_long_func: %lld\n", really_long_func());
}

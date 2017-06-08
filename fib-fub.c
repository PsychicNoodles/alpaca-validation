#include <stdio.h>
#include <stdlib.h>

#define CYCLES 1000

int fib(int n) {
  if (n == 0) return 1;
  if (n == 1) return 1;
  return fib(n - 1) + fib(n - 2);
}

/*double fub(int n) {
  if (n == 0) return 1.1;
  if (n == 1) return 1.1;
  return fub(n - 1) + fub(n - 2);
}*/

void usage(char* progname) {
  fprintf(stderr, "Usage: %s N D\n", progname);
  fprintf(stderr, "  N of every D iterations will call a double-precision fibonacci function rather than the integer version.\n");
  fprintf(stderr, "  N must be >= 0 and <= D. D must be > 0.\n");
}

int main(int argc, char** argv) {
  if (argc < 3) {
    usage(argv[0]);
    return 1;
  }

  int N = atoi(argv[1]);
  int D = atoi(argv[2]);

  if (N < 0 || D < 1 || N > D) {
    usage(argv[0]);
    return 1;
  }
  
  int isum = 0;
  //double dsum = 0;
  
  for (int i = 0; i < CYCLES; i++) {
    if (i % D < N) {
      isum += fib(20);
    } else {
      isum += fib(20);
    }
  }
  
  return 0;
}

#include <stdio.h>

double fake_func() {
        printf("fake\n");
        return 2.2468/2.0;
}

int main () {
        printf("Entered main at address %p with fake_func at %p\n", main, (void*) fake_func);
        printf("fake_func(): %f\n", fake_func());
        return 0; 
}


#include <stdio.h>

int test;

int fake_func() {
        printf("fake\n");
        test = 22;
        return test; 
}

int main () {
        printf("Entered main at address %p with fake_func at %p\n", main, (void*) fake_func);
        test = 10;
        printf("fake_func(): %d\n", fake_func());
        return 0; 
}


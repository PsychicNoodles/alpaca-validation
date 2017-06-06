#include <stdio.h>

int test;

int fake_func() {
        printf("fake\n");
        test = 22;
        return test; 
}

int main () {
        printf("Entered main at address: %p\n", main);
        test = 10;
        fake_func();
        return 0; 
}

